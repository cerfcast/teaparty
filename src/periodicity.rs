use slog::{error, info, Logger};

use crate::os::get_mac_address;
use crate::server::Sessions;
use crate::stamp::{StampMsgBody, MBZ_VALUE};
use crate::{server::ServerSocket, stamp::StampMsg, HeartbeatConfiguration};
use crate::{tlv, NtpTime};
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

pub fn periodicity(
    socket: ServerSocket,
    heartbeats: Vec<HeartbeatConfiguration>,
    sessions: Sessions,
    sessions_cleanup_duration: Duration,
    logger: Logger,
) {
    let mut fs: Vec<_> = heartbeats
        .iter()
        .filter_map(|hb| {
            let hb = hb.clone();
            let socket = socket.clone();

            let mac = get_mac_address(socket.clone(), hb.target);
            if let Ok(mac) = mac {
                Some(thread::spawn(move || loop {
                    thread::sleep(Duration::from_secs(hb.interval));

                    let heartbeat = StampMsg {
                        sequence: 0x22,
                        time: NtpTime::now(),
                        error: Default::default(),
                        ssid: Default::default(),
                        body: TryInto::<StampMsgBody>::try_into([MBZ_VALUE; 30].as_slice()).unwrap(),
                        tlvs: vec![tlv::Tlv::heartbeat(mac.clone())],
                        malformed: None,
                    };

                    {
                        let socket = socket.socket.lock().unwrap();
                        if let IpAddr::V4(v4) = hb.target.ip() {
                            //LOGIT!
                            let _ = socket.send_to(&Into::<Vec<u8>>::into(heartbeat), (v4, hb.target.port()));
                        }
                    }
                }))
            } else {
                error!(logger, "Could not get the MAC address of the network card for sending heartbeats to {:?}; will not send them.", hb.target);
                None
            }
        })
        .collect();

    fs.push(thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(1));
        info!(logger, "Checking for stale sessions.");
        {
            let mut sessions = sessions.sessions.lock().unwrap();
            for session in sessions.clone().keys() {
                info!(logger, "Session last referenced at: {:?}", session.last());
                if std::time::SystemTime::now()
                    .duration_since(session.last())
                    .unwrap()
                    > sessions_cleanup_duration
                {
                    info!(
                        logger,
                        "Session (source ip: {}, dst ip: {}, ssid: {:?}, sequence: {}) is too old, removing it.",
                        session.src,
                        session.dst,
                        session.ssid,
                        sessions.get(session).unwrap().sequence
                    );
                    sessions.remove(session);
                }
            }
        }
    }));
    for handle in fs {
        let _ = handle.join();
    }
}
