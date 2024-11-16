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
};

use nix::sys::socket::{sendto, MsgFlags, SockaddrIn};


pub struct Responder {
}

impl Responder {
    pub fn new() -> Self {
        Responder { }
    }

    pub fn write(
        &self,
        data: &[u8],
        socket: &UdpSocket,
        addr: SockaddrIn,
    ) -> Result<usize, std::io::Error> {
        sendto(socket.as_raw_fd(), data, &addr, MsgFlags::empty())
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
