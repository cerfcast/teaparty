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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::monitor::Monitor;
use crate::server::{ServerCancellation, Session, SessionData, SessionError};
use crate::stamp::Ssid;
use rocket::http::Status;
use rocket::serde::{json::Json, Deserialize};
use rocket::State;
use serde::Serialize;
use slog::Logger;

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
    key: String,
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
    sd.key = Some(Vec::<u8>::from(request.key.clone()));

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

pub fn launch_meta(monitor: Monitor, _server_cancellation: ServerCancellation, logger: Logger) {
    {
        let logger = logger.clone();
        let joinable = std::thread::spawn(move || {
            slog::info!(logger, "Starting the meta thread!");
            let r = rocket::build()
                .configure(rocket::Config::release_default())
                .manage(monitor)
                .mount("/", routes![index, heartbeats, stop_heartbeat, session])
                .launch();

            let rt = rocket::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Uh oh!");
            rt.block_on(r).expect("Could not start!");
        });
        joinable.join().unwrap();
    }
    slog::info!(logger, "Stopping the meta thread!");
}
