/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2024  Will Hawkins and Cerfcast
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

use std::{
    collections::HashMap,
    net::{self, UdpSocket},
    sync::{Arc, Mutex},
};

use nix::sys::socket::SockaddrIn;
use serde::{ser::SerializeStruct, Serialize};
use std::hash::Hash;

use crate::stamp::Ssid;

#[derive(Debug, Clone)]
pub struct Session {
    pub src: SockaddrIn,
    pub dst: SockaddrIn,
    pub ssid: Ssid,
    last: std::time::SystemTime,
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let srcs = self.src.to_string();
        let dsts = self.dst.to_string();
        let mut struct_serializer = serializer.serialize_struct("Session", 4)?;
        struct_serializer.serialize_field("src", &srcs)?;
        struct_serializer.serialize_field("dst", &dsts)?;
        struct_serializer.serialize_field("ssid", &self.ssid)?;
        struct_serializer.serialize_field("last", &self.last)?;
        struct_serializer.end()
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.dst == other.dst && self.src == other.src && self.ssid == other.ssid
    }
}

impl Hash for Session {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Hash::hash(&self.src, state);
        Hash::hash(&self.dst, state);
        Hash::hash(&self.ssid, state);
    }
}

impl Eq for Session {}

#[derive(Serialize, Debug, Copy, Clone, Default)]
pub struct SessionData {
    pub sequence: u32,
}

impl SessionData {
    pub fn new() -> SessionData {
        Self { sequence: 0u32 }
    }
}

impl Session {
    pub fn new(src: SockaddrIn, dst: SockaddrIn, ssid: Ssid) -> Self {
        Self {
            src,
            dst,
            last: std::time::SystemTime::now(),
            ssid,
        }
    }

    pub fn reference(&mut self) {
        self.last = std::time::SystemTime::now()
    }

    pub fn last(&self) -> std::time::SystemTime {
        self.last
    }
}

impl ToString for Session {
    fn to_string(&self) -> String {
        self.ssid.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct Sessions {
    pub sessions: Arc<Mutex<HashMap<Session, SessionData>>>,
}

impl Serialize for Sessions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct EmbeddedSession {
            id: Session,
            data: SessionData,
        }

        let sessions = self.sessions.lock().unwrap();

        let embedded_sessions: Vec<_> = sessions.iter().map(|v| EmbeddedSession {
            id: v.0.clone(),
            data: v.1.clone(),
        }).collect();
        serde::Serialize::serialize(&embedded_sessions, serializer)
    }
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::<HashMap<Session, SessionData>>::new(HashMap::<
                Session,
                SessionData,
            >::new(
            ))),
        }
    }
}

#[derive(Clone)]
pub struct ServerSocket {
    pub socket: Arc<Mutex<UdpSocket>>,
    pub socket_addr: net::SocketAddr,
}

impl ServerSocket {
    pub fn new(socket: UdpSocket, addr: net::SocketAddr) -> Self {
        Self {
            socket: Arc::new(Mutex::new(socket)),
            socket_addr: addr,
        }
    }
}
