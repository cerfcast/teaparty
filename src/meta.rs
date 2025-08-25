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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

use crate::app::{ServerError, TeapartyError};
use crate::monitor::Monitor;
use crate::server::{ServerCancellation, Session, SessionData, SessionError};
use crate::stamp::Ssid;
use crate::tlvs::biterrorrate::BitPattern;
use rocket::http::Status;
use rocket::serde::{json::Json, Deserialize};
use rocket::{Config, State};
use serde::Serialize;
use slog::Logger;
use slog::{error, info};
use yaml_rust2::Yaml;

#[derive(Clone, Debug)]
pub struct MetaSocketAddr<const T: u16> {
    pub addr: SocketAddr,
}

impl<const T: u16> Default for MetaSocketAddr<T> {
    fn default() -> Self {
        Self {
            addr: (Ipv4Addr::UNSPECIFIED, T).into(),
        }
    }
}
impl<const T: u16> MetaSocketAddr<T> {
    pub const DEFAULT_PORT: u16 = T;
}

impl<const T: u16> From<SocketAddr> for MetaSocketAddr<T> {
    fn from(value: SocketAddr) -> Self {
        MetaSocketAddr {
            addr: (
                value.ip(),
                if value.port() != 0 {
                    value.port()
                } else {
                    MetaSocketAddr::<T>::DEFAULT_PORT
                },
            )
                .into(),
        }
    }
}
impl<const T: u16> FromStr for MetaSocketAddr<T> {
    type Err = clap::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First, split at last :
        let splits: Vec<_> = s.split(':').collect();

        // We'll try to consider that a port.
        if let Some(maybe_port) = splits.last() {
            // That means that all the values before it are part of an IP address.
            let ip = splits[0..splits.len() - 1].join(":");

            // If that worked, then we're in business.
            if let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), maybe_port.parse::<u16>()) {
                return Ok(MetaSocketAddr {
                    addr: (ip, port).into(),
                });
            }
        }

        // Otherwise, it _seems_ like everything that was given by the user is an IP!
        let ip = s
            .parse::<IpAddr>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
        Ok(MetaSocketAddr {
            addr: (ip, Self::DEFAULT_PORT).into(),
        })
    }
}

impl<const T: u16> TryInto<MetaSocketAddr<T>> for &Yaml {
    type Error = TeapartyError;

    fn try_into(self) -> Result<MetaSocketAddr<T>, Self::Error> {
        if let Some(yaml) = self.as_hash() {
            let mut addr = Into::<SocketAddr>::into((Ipv4Addr::UNSPECIFIED, 0));

            if let Some(value) = yaml
                .get(&Yaml::String("ip".to_string()))
                .and_then(|f| f.as_str())
            {
                addr.set_ip(value.parse::<IpAddr>().map_err(|e| {
                    TeapartyError::Server(ServerError::Config(format!(
                        "Could not parse IP address: {e}"
                    )))
                })?)
            }
            if let Some(value) = yaml
                .get(&Yaml::String("port".to_string()))
                .and_then(|f| f.as_i64())
            {
                addr.set_port(u16::try_from(value).map_err(|e| {
                    TeapartyError::Server(ServerError::Config(format!(
                        "Could not parse port number: {e}"
                    )))
                })?)
            }
            Ok(MetaSocketAddr { addr })
        } else {
            Err(TeapartyError::Server(ServerError::Config(
                "Invalid configuration for socket address".to_string(),
            )))
        }
    }
}

#[get("/sessions")]
fn index(monitor: &State<Monitor>) -> String {
    serde_json::to_string(&monitor.sessions)
        .unwrap()
        .to_string()
}

#[derive(Deserialize, Serialize)]
struct SessionRequest {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ssid: u16,
    key: Option<String>,
    ber: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct HeartbeatTargetRequest {
    target: Ipv4Addr,
    port: u16,
}

#[post("/session", data = "<request>")]
fn session(request: Json<SessionRequest>, monitor: &State<Monitor>) -> Result<String, Status> {
    let sessions = &monitor.sessions;

    if sessions.is_none() {
        return Err(rocket::http::Status::InternalServerError);
    }

    let sessions = sessions.as_ref().unwrap();

    let s = Session::new(
        SocketAddrV4::new(request.src_ip, request.src_port).into(),
        SocketAddrV4::new(request.dst_ip, request.dst_port).into(),
        Ssid::Ssid(request.ssid),
    );

    let mut sd = SessionData::new(None);

    // Configure the optional bits of the session.
    if let Some(key) = request.key.as_ref() {
        if !key.is_empty() {
            sd.key = Some(Vec::<u8>::from(key.as_bytes()));
        }
    }
    if let Some(ber) = request.ber.as_ref() {
        if !ber.is_empty() {
            if let Ok(ber) = ber.parse::<BitPattern>() {
                sd.ber = Some(ber);
            }
        }
    }

    match sessions.maybe_new(s, sd) {
        Ok(()) => Ok(serde_json::to_string(&request.0).unwrap()),
        Err(SessionError::SessionExists) => Err(rocket::http::Status::InternalServerError),
    }
}

#[post("/stop_heartbeat", data = "<request>")]
fn stop_heartbeat(request: Json<HeartbeatTargetRequest>, monitor: &State<Monitor>) -> String {
    monitor
        .periodic
        .stop_heartbeater(SocketAddr::from((request.target, request.port)))
        .unwrap();
    let heartbeats_info = monitor.periodic.get_heartbeaters_info();
    serde_json::to_string(&heartbeats_info).unwrap().to_string()
}

#[get("/heartbeats")]
fn heartbeats(monitor: &State<Monitor>) -> String {
    let heartbeats_info = monitor.periodic.get_heartbeaters_info();
    serde_json::to_string(&heartbeats_info).unwrap().to_string()
}

pub fn launch_meta(
    monitor: Monitor,
    listen_on: SocketAddr,
    _server_cancellation: ServerCancellation,
    logger: Logger,
) {
    {
        let rocket_config = Config {
            address: listen_on.ip(),
            port: listen_on.port(),
            ..Config::release_default()
        };
        let thread_logger = logger.clone();
        let joinable = std::thread::spawn(move || {
            info!(thread_logger, "Starting the meta thread!");
            let r = rocket::build()
                .configure(rocket_config)
                .manage(monitor)
                .mount("/", routes![index, heartbeats, stop_heartbeat, session])
                .launch();

            match rocket::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    if let Err(meta_start_error) = rt.block_on(r) {
                        error!(
                            thread_logger,
                            "Could not start the meta thread: {meta_start_error}"
                        );
                    };
                }
                Err(e) => {
                    error!(
                        thread_logger,
                        "There was an error building the meta thread's Rocket runtime: {e}"
                    );
                }
            };
        });

        match joinable.join() {
            Err(joinable_launch_error) => {
                info!(logger, "Could not wait for the meta server to shut down (maybe it didn't start properly?): {joinable_launch_error:?}.");
            }
            Ok(_) => {
                info!(logger, "meta server is shut down.");
            }
        }
    }
}
