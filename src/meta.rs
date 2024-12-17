use std::net::{Ipv4Addr, SocketAddrV4};

use crate::monitor::Monitor;
use crate::server::{Session, SessionData, SessionError};
use crate::stamp::Ssid;
use nix::sys::socket::SockaddrIn;
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

#[post("/session", data = "<request>")]
fn session(request: Json<SessionRequest>, monitor: &State<Monitor>) -> Result<String, Status> {
    let sessions = &monitor.sessions;

    let s = Session::new(
        Into::<SockaddrIn>::into(SocketAddrV4::new(request.src_ip, request.src_port)),
        Into::<SockaddrIn>::into(SocketAddrV4::new(request.dst_ip, request.dst_port)),
        Ssid::Ssid(request.ssid),
    );

    let mut sd = SessionData::new();
    sd.key = Some(Vec::<u8>::from(request.key.clone()));

    match sessions.maybe_new(s, sd) {
        Ok(()) => Ok(serde_json::to_string(&request.0).unwrap()),
        Err(SessionError::SessionExists) => Err(rocket::http::Status::InternalServerError),
    }
}

#[get("/heartbeats")]
fn heartbeats(monitor: &State<Monitor>) -> String {
    let heartbeats_info = monitor.periodic.get_heartbeaters_info();
    serde_json::to_string(&heartbeats_info).unwrap().to_string()
}

pub fn launch_meta(monitor: Monitor, logger: Logger) {
    {
        let logger = logger.clone();
        let joinable = std::thread::spawn(move || {
            slog::info!(logger, "Starting the meta thread!");
            let r = rocket::build()
                .configure(rocket::Config::release_default())
                .manage(monitor)
                .mount("/", routes![index, heartbeats, session])
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
