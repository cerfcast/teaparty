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
