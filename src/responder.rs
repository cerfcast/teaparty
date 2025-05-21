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

use std::{
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::{mpsc::channel, Arc, Mutex},
    time::Duration,
};

use nix::sys::socket::{sendto, MsgFlags};
use slog::Logger;
use slog::{error, info};
use std::sync::mpsc::{Receiver, Sender};

use crate::{
    handlers::Handlers,
    netconf::NetConfiguration,
    server::{ServerSocket, Session, Sessions},
    stamp::StampMsg,
    util::to_sockaddr_storage,
};

pub struct Responder {
    #[allow(clippy::type_complexity)]
    recv: Arc<
        Mutex<
            std::sync::mpsc::Receiver<(
                StampMsg,
                NetConfiguration,
                SocketAddr,
                SocketAddr,
                Option<Handlers>,
            )>,
        >,
    >,
    #[allow(clippy::type_complexity)]
    send: Arc<
        Mutex<
            std::sync::mpsc::Sender<(
                StampMsg,
                NetConfiguration,
                SocketAddr,
                SocketAddr,
                Option<Handlers>,
            )>,
        >,
    >,
    sessions: Option<Sessions>,
}

impl Responder {
    pub fn new(sessions: Option<Sessions>) -> Self {
        #[allow(clippy::type_complexity)]
        let (tx, rx): (
            Sender<(
                StampMsg,
                NetConfiguration,
                SocketAddr,
                SocketAddr,
                Option<Handlers>,
            )>,
            Receiver<(
                StampMsg,
                NetConfiguration,
                SocketAddr,
                SocketAddr,
                Option<Handlers>,
            )>,
        ) = channel();
        Responder {
            recv: Arc::new(Mutex::new(rx)),
            send: Arc::new(Mutex::new(tx)),
            sessions,
        }
    }

    pub fn write(
        &self,
        data: &[u8],
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<usize, std::io::Error> {
        let saddr = to_sockaddr_storage(addr);
        sendto(socket.as_raw_fd(), data, &saddr, MsgFlags::empty())
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    pub fn respond(
        &self,
        msg: StampMsg,
        handlers: Option<Handlers>,
        config: NetConfiguration,
        src: SocketAddr,
        dest: SocketAddr,
    ) {
        let send = self.send.lock().unwrap();
        send.send((msg, config, src, dest, handlers))
            .expect("Should have been able to send message");
    }

    pub fn run(
        &self,
        server: ServerSocket,
        cancelled: Arc<std::sync::atomic::AtomicBool>,
        logger: Logger,
    ) {
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                info!(logger, "Responder is stopping!");
                break;
            }

            let r = {
                let recv = self.recv.lock().unwrap();
                match recv.recv_timeout(Duration::from_millis(500)) {
                    Ok(value) => Some(value),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                    Err(e) => {
                        error!(logger, "There was an error waiting for a message: {}", e);
                        break;
                    }
                }
            };

            if r.is_none() {
                continue;
            }

            let (mut stamp_msg, mut netconfig, src, dest, handlers) = r.unwrap();

            // Moved from handler

            let mut modified_src = src;

            // Let each of the handlers have the chance to modify the socket from which the response will be sent.
            for response_tlv in stamp_msg.tlvs.tlvs.clone().iter() {
                if let Some(response_tlv_handler) = handlers
                    .as_ref()
                    .and_then(|handler| handler.get_handler(response_tlv.tpe))
                {
                    modified_src = response_tlv_handler
                        .lock()
                        .unwrap()
                        .prepare_response_target(&mut stamp_msg, modified_src, logger.clone());
                }
            }

            // If there was a change requested, handle that request now.
            let response_src_socket = if src != modified_src {
                let response_src_socket = UdpSocket::bind((modified_src.ip(), modified_src.port()));

                info!(
                    logger,
                    "A handler wanted to change the response's source to {}", modified_src
                );

                if let Err(e) = response_src_socket {
                    error!(
                logger,
                "There was an error binding the response source socket: {}. Abandoning response.",
                e
            );
                    return;
                }

                Arc::new(Mutex::new(response_src_socket.unwrap()))
            } else {
                server.socket.clone()
            };

            // It's possible that the handlers also want to add some special configuration to the socket, too.
            let response_result = {
                // Take a lock on the socket that we are going to use to send the response packet. We do this locking
                // because the handlers may want to make a change to the socket's configuration and attempting to
                // read packets in this configuration could cause a problem.

                let locked_socket_to_prepare = response_src_socket.lock().unwrap();

                let query_session = Session::new(dest, src, stamp_msg.ssid.clone());
                let maybe_session_data = self
                    .sessions
                    .as_ref()
                    .and_then(|v| v.sessions.lock().unwrap().get(&query_session).cloned());

                for tlv_tpe in stamp_msg.tlvs.type_iter() {
                    if let Some(response_tlv_handler) = handlers
                        .as_ref()
                        .and_then(|handler| handler.get_handler(tlv_tpe))
                    {
                        if let Err(e) = response_tlv_handler.lock().unwrap().pre_send_fixup(
                            &mut stamp_msg,
                            &locked_socket_to_prepare,
                            &maybe_session_data,
                            logger.clone(),
                        ) {
                            error!(logger, "There was an error letting handlers do their final response fixups: {}. Abandoning response.", e);
                            return;
                        }
                    }
                }

                if let Err(e) = netconfig.configure(
                    &mut stamp_msg,
                    &locked_socket_to_prepare,
                    handlers.clone(),
                    logger.clone(),
                ) {
                    error!(logger, "There was an error performing net configuration on a reflected packet: {}; Abandoning response.", e);
                    return;
                }

                info!(logger, "Responding with stamp msg: {:x?}", stamp_msg);

                let write_result = {
                    self.write(
                        &Into::<Vec<u8>>::into(stamp_msg.clone()),
                        &locked_socket_to_prepare,
                        dest,
                    )
                };

                if let Err(e) = netconfig.unconfigure(&locked_socket_to_prepare, logger.clone()) {
                    error!(logger, "There was an error performing net unconfiguration: {}. Such a situation is bad.", e);
                    return;
                }

                write_result
            };

            if response_result.is_err() {
                error!(
                    logger,
                    "An error occurred sending the response: {}",
                    response_result.unwrap_err()
                );
                continue;
            }

            info!(
                logger,
                "Sent {} bytes as a response.",
                response_result.unwrap()
            );
        }
    }
}
