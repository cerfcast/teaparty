use crate::stamp::{StampMsgBody, MBZ_VALUE};
use crate::{server::ServerSocket, stamp::StampMsg, HeartbeatConfiguration};
use crate::{tlv, NtpTime};
use std::net::IpAddr;
use std::{thread, time::Duration};

pub fn periodicity(socket: ServerSocket, heartbeats: Vec<HeartbeatConfiguration>) {
    let fs: Vec<_> = heartbeats
        .iter()
        .map(|hb| {
            let hb = hb.clone();
            let socket = socket.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(hb.interval));

                let heartbeat = StampMsg {
                    sequence: 0x22,
                    time: NtpTime::now(),
                    error: Default::default(),
                    ssid: Default::default(),
                    body: TryInto::<StampMsgBody>::try_into([MBZ_VALUE; 30].as_slice()).unwrap(),
                    tlvs: vec![tlv::Tlv::heartbeat()],
                    malformed: None,
                };

                {
                    let socket = socket.socket.lock().unwrap();
                    if let IpAddr::V4(v4) = hb.target {
                        //LOGIT!
                        let _ = socket.send_to(&Into::<Vec<u8>>::into(heartbeat), (v4, 862));
                    }
                }
            })
        })
        .collect();
    for handle in fs {
        let _ = handle.join();
    }
}
