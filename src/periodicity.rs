/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2024, 2025  Will Hawkins and Cerfcast
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use serde::Serialize;
use slog::{error, info, Logger};

use crate::os::{get_mac_address, MacAddr};
use crate::server::Sessions;
use crate::stamp::{StampMsgBody, MBZ_VALUE};
use crate::tlv::Tlvs;
use crate::{server::ServerSocket, stamp::StampMsg, HeartbeatConfiguration};
use crate::{tlv, NtpTime};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[allow(clippy::type_complexity, unused)]
#[derive(Debug, Clone)]
pub struct Periodicity {
    heartbeaters: std::sync::Arc<
        std::sync::Mutex<HashMap<SocketAddr, (std::sync::mpsc::Sender<bool>, JoinHandle<()>)>>,
    >,
    heartbeaters_info: std::sync::Arc<std::sync::Mutex<HashMap<SocketAddr, std::time::Duration>>>,
    stale_sender: Sender<bool>,
    stale_joiner: std::sync::Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Clone, Serialize)]
pub struct HeartbeatInfo {
    target: SocketAddr,
    interval: Duration,
}

impl Periodicity {
    pub fn get_heartbeaters_info(&self) -> std::vec::Vec<HeartbeatInfo> {
        self.heartbeaters_info
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .map(|(k, v)| HeartbeatInfo {
                target: k,
                interval: v,
            })
            .collect()
    }

    fn launch_heartbeater(
        socket: ServerSocket,
        addr: SocketAddr,
        interval: Duration,
        logger: Logger,
        mac: MacAddr,
    ) -> (Sender<bool>, JoinHandle<()>) {
        let (sender, receiver) = std::sync::mpsc::channel::<bool>();
        let joiner = thread::spawn(move || {
            loop {
                let mut is_cancelled = false;
                match receiver.try_recv() {
                    Err(TryRecvError::Disconnected) => {
                        info!(
                            logger,
                            "Sender disconnected from thread sender; cancelling."
                        );
                        is_cancelled = true;
                    }
                    Err(TryRecvError::Empty) => {
                        // Don't do anything ... this is not really an error.
                    }
                    Ok(_) => {
                        info!(logger, "Sender sent cancellation message.");
                        is_cancelled = true;
                    }
                };

                if is_cancelled {
                    break;
                }

                thread::sleep(interval);

                let tlvs = Tlvs {
                    tlvs: vec![tlv::Tlv::heartbeat(mac)],
                    malformed: None,
                };

                let heartbeat = StampMsg {
                    sequence: 0x22,
                    time: NtpTime::now(),
                    error: Default::default(),
                    ssid: Default::default(),
                    body: TryInto::<StampMsgBody>::try_into([MBZ_VALUE; 30].as_slice()).unwrap(),
                    hmac: None,
                    tlvs,
                };

                info!(logger, "Sending heartbeat to {:?}", addr);
                {
                    let socket = socket.socket.lock().unwrap();
                    //LOGIT!
                    let _ = socket.send_to(&Into::<Vec<u8>>::into(heartbeat), addr);
                }
            }
            info!(logger, "Heartbeater targeting {:?} is ending", addr);
        });

        (sender, joiner)
    }

    pub fn new(
        socket: ServerSocket,
        heartbeats: Vec<HeartbeatConfiguration>,
        sessions: Option<Sessions>,
        sessions_cleanup_duration: Duration,
        logger: Logger,
    ) -> Self {
        let mut heartbeaters =
            HashMap::<SocketAddr, (std::sync::mpsc::Sender<bool>, JoinHandle<()>)>::new();

        let mut heartbeaters_info = HashMap::<SocketAddr, std::time::Duration>::new();

        heartbeats.iter().for_each(|hb| {
            let mut target_addr: Option<SocketAddr> = None;

            if let IpAddr::V4(v4) = hb.target.ip() {
                target_addr = Some((v4, hb.target.port()).into());
            }
            let mac = get_mac_address(socket.clone(), hb.target, logger.clone());

            if let (Ok(mac), Some(target_addr)) = (mac, target_addr) {
                let (sender, joiner) = Periodicity::launch_heartbeater(
                    socket.clone(),
                    target_addr,
                    std::time::Duration::from_secs(hb.interval),
                    logger.clone(),
                    mac,
                );
                heartbeaters.insert(target_addr, (sender, joiner));
                heartbeaters_info.insert(target_addr, std::time::Duration::from_secs(hb.interval));
            } else {
                error!(
                    logger,
                    "Could not launch the heartbeater targeting {:?}; will not send them.",
                    hb.target
                );
            }
        });

        let (stale_sender, stale_receiver) = std::sync::mpsc::channel::<bool>();
        let stale_joiner = thread::spawn(move || {
            if sessions.as_ref().is_none() {
                return;
            }

            loop {
                let mut is_cancelled = false;
                match stale_receiver.try_recv() {
                    Err(TryRecvError::Disconnected) => {
                        info!(
                            logger,
                            "Sender disconnected from thread sender; cancelling."
                        );
                        is_cancelled = true;
                    }
                    Err(TryRecvError::Empty) => {
                        // Don't do anything ... this is not really an error.
                    }
                    Ok(_) => {
                        info!(logger, "Sender sent cancellation message.");
                        is_cancelled = true;
                    }
                };

                if is_cancelled {
                    break;
                }

                thread::sleep(std::time::Duration::from_secs(1));
                info!(logger, "Checking for stale sessions.");
                {
                    let mut sessions = sessions.as_ref().unwrap().sessions.lock().unwrap();
                    for (session, data) in sessions.clone().iter() {
                        info!(logger, "Session last referenced at: {:?}", data.last);
                        if std::time::SystemTime::now()
                            .duration_since(data.last)
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
            }
        });

        Self {
            heartbeaters: std::sync::Arc::new(std::sync::Mutex::new(heartbeaters)),
            heartbeaters_info: std::sync::Arc::new(std::sync::Mutex::new(heartbeaters_info)),
            stale_sender,
            stale_joiner: std::sync::Arc::new(std::sync::Mutex::new(Some(stale_joiner))),
        }
    }

    #[allow(unused)]
    pub fn stop_heartbeater(&mut self, addr: SocketAddr) -> Result<(), std::io::Error> {
        let mut heartbeaters = self.heartbeaters.lock().unwrap();

        let (_, (sender, handle)) = heartbeaters
            .remove_entry(&addr)
            .ok_or::<std::io::Error>(std::io::ErrorKind::AddrNotAvailable.into())?;
        sender
            .send(true)
            .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;
        handle
            .join()
            .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;

        Ok(())
    }

    #[allow(unused)]
    pub fn stop(&mut self) -> Result<(), std::io::Error> {
        self.stale_sender
            .send(true)
            .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;

        let mut r = self
            .stale_joiner
            .lock()
            .map_err(|_| Into::<std::io::Error>::into(std::io::ErrorKind::InvalidData))?;

        r.take().map(|f| Some(f.join()));

        Ok(())
    }
}
