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
    net::UdpSocket,
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
};

use nix::sys::socket::{sendto, MsgFlags, SockaddrIn};

pub struct Responder {
    socket: Arc<UdpSocket>,
    mutex: Mutex<u64>,
}

impl Responder {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Responder {
            socket,
            mutex: Mutex::new(0),
        }
    }

    pub fn write(
        &self,
        data: &[u8],
        socket: Option<UdpSocket>,
        addr: SockaddrIn,
    ) -> Result<usize, std::io::Error> {
        let lock = self.mutex.lock();

        if lock.is_err() {
            return Err(std::io::ErrorKind::Interrupted.into());
        }

        match socket {
            Some(updated_src_socket) => sendto(
                updated_src_socket.as_raw_fd(),
                data,
                &addr,
                MsgFlags::empty(),
            )
            .map_err(|e| std::io::Error::other(e.to_string())),
            None => sendto(self.socket.as_raw_fd(), data, &addr, MsgFlags::empty())
                .map_err(|e| std::io::Error::other(e.to_string())),
        }
    }
}
