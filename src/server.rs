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

use crate::stamp::Ssid;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Session {
    pub src: SockaddrIn,
    pub dst: SockaddrIn,
    pub ssid: Ssid,
    last: std::time::SystemTime,
}

#[derive(Debug, Copy, Clone, Default)]
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

#[derive(Clone)]
pub struct Sessions {
    pub sessions: Arc<Mutex<HashMap<Session, SessionData>>>,
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
