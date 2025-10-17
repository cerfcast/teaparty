/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2025  Will Hawkins and Cerfcast
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
    fmt::Debug,
    io::{ErrorKind, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    time,
};

use etherparse::{
    Ethernet2Header, Ipv4Header, Ipv6Header, LinkSlice, NetSlice, SlicedPacket, TransportSlice,
};
use mio::{Events, Interest};
use nix::{
    errno::Errno,
    sys::socket::{recvmsg, ControlMessageOwned, Ipv6ExtHeader, MsgFlags, SockaddrStorage},
};
use pnet::datalink::DataLinkReceiver;
use slog::{error, info, trace, warn};

use crate::{
    ip::{DscpValue, EcnValue, ExtensionHeader},
    server::ServerSocket,
    util::to_socketaddr,
};

#[derive(Debug)]
pub enum ConnectionGeneratorError {
    Filtered,
    ExtractionError,
    WouldBlock,
    IoError(std::io::Error),
}

pub enum ConnectionGeneratorSource {
    LinkLayer(Box<dyn DataLinkReceiver>),
    InternetLayer(ServerSocket),
}

pub struct ConnectionGenerator {
    connection: ConnectionGeneratorSource,
    poller: Option<mio::Poll>,
}

impl ConnectionGenerator {
    const SOCKET_POLL_TOKEN: mio::Token = mio::Token(1);

    pub fn configure_polling(&mut self) -> Result<(), std::io::Error> {
        match &self.connection {
            ConnectionGeneratorSource::LinkLayer(_) => Ok(()),
            ConnectionGeneratorSource::InternetLayer(socket) => {
                let socket_raw_fd = {
                    let socket = socket.socket.lock().unwrap();
                    socket.as_raw_fd()
                };
                let poller = mio::Poll::new()?;

                poller.registry().register(
                    &mut mio::unix::SourceFd(&socket_raw_fd),
                    Self::SOCKET_POLL_TOKEN,
                    Interest::READABLE,
                )?;
                self.poller = Some(poller);
                Ok(())
            }
        }
    }
}

impl From<Box<dyn DataLinkReceiver>> for ConnectionGenerator {
    fn from(value: Box<dyn DataLinkReceiver>) -> Self {
        Self {
            connection: ConnectionGeneratorSource::LinkLayer(value),
            poller: None,
        }
    }
}

impl From<ServerSocket> for ConnectionGenerator {
    fn from(value: ServerSocket) -> Self {
        Self {
            connection: ConnectionGeneratorSource::InternetLayer(value),
            poller: None,
        }
    }
}

pub type ExtendedIpv6Header = (Ipv6Header, Vec<Ipv6ExtHeader>);
pub type IpHeaders = either::Either<Ipv4Header, ExtendedIpv6Header>;

#[derive(Debug, Clone)]
pub enum IpVersion {
    Four,
    Six,
}

#[derive(Debug, Clone)]
pub struct NetworkOptions {
    pub mode: IpVersion,
    pub ttl: u8,
    pub dscp: DscpValue,
    pub ecn: EcnValue,
    pub extension_headers: Option<Vec<ExtensionHeader>>,
}

#[derive(Debug, Clone)]
pub struct ConnectionInformation {
    pub ethernet: Option<Ethernet2Header>,
    pub raw_network: Option<Vec<u8>>,
    pub network: NetworkOptions,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub information: ConnectionInformation,
    pub body: Vec<u8>,
    pub addr: SocketAddr,
}

impl ConnectionGenerator {
    fn extract_packets(pkt: &[u8]) -> Option<(Connection, SocketAddr)> {
        match SlicedPacket::from_ethernet(pkt) {
            Ok(pieces) => {
                let link_header = if let Some(LinkSlice::Ethernet2(ether)) = pieces.link {
                    ether.to_header().clone()
                } else {
                    return None;
                };

                match (pieces.net, pieces.transport) {
                    (Some(NetSlice::Ipv4(ipv4)), Some(TransportSlice::Udp(udp))) => {
                        let ipv4 = ipv4.header();
                        let client_address: SocketAddr =
                            (ipv4.source_addr(), udp.source_port()).into();
                        let target_address: SocketAddr =
                            (ipv4.destination_addr(), udp.destination_port()).into();
                        let raw_net_header = ipv4.slice().to_vec();
                        let ttl = ipv4.ttl();
                        let dscp: DscpValue = ipv4.dcp().try_into().unwrap();
                        let ecn: EcnValue = ipv4.ecn().into();
                        let mode = IpVersion::Four;
                        Some((
                            Connection {
                                information: ConnectionInformation {
                                    ethernet: Some(link_header),
                                    raw_network: Some(raw_net_header),
                                    network: NetworkOptions {
                                        mode,
                                        ttl,
                                        dscp,
                                        ecn,
                                        extension_headers: None,
                                    },
                                },
                                body: udp.payload().to_vec(),
                                addr: client_address,
                            },
                            target_address,
                        ))
                    }
                    _ => {
                        // Todo: Handle IPv6
                        None
                    }
                }
            }
            _ => None,
        }
    }

    fn packet_filter(
        mode: IpVersion,
        target_address: SocketAddr,
        server_address: SocketAddr,
        logger: slog::Logger,
    ) -> bool {
        match mode {
            IpVersion::Four => {
                if !server_address.ip().is_unspecified()
                    && target_address.ip() != server_address.ip()
                {
                    trace!(
                        logger,
                        "Got a udp packet that was not for our IP (expected {}, got {}). Skipping",
                        target_address.ip(),
                        server_address.ip()
                    );
                    return false;
                }
            }
            IpVersion::Six => {
                trace!(
                    logger,
                    "Packet filtering for Ipv6 is not yet implemented. Skipping."
                );
                return false;
            }
        }

        if target_address.port() != server_address.port() {
            trace!(
                logger,
                "Got a udp packet that was not for our port ({}). Skipping",
                target_address.port()
            );
            return false;
        }
        true
    }

    pub fn next(
        &mut self,
        logger: slog::Logger,
        server_socket_addr: SocketAddr,
    ) -> Result<Connection, ConnectionGeneratorError> {
        match &mut self.connection {
            ConnectionGeneratorSource::LinkLayer(interface) => match interface.next() {
                Ok(pkt) => {
                    if let Some((connection, target_addr)) = Self::extract_packets(pkt) {
                        if !Self::packet_filter(
                            connection.information.network.mode.clone(),
                            target_addr,
                            server_socket_addr,
                            logger.clone(),
                        ) {
                            trace!(
                                logger,
                                "Skipping a received packet because it was filtered."
                            );
                            return Err(ConnectionGeneratorError::Filtered);
                        }
                        Ok(connection)
                    } else {
                        Err(ConnectionGeneratorError::ExtractionError)
                    }
                }
                Err(e) => Err(ConnectionGeneratorError::IoError(e)),
            },
            ConnectionGeneratorSource::InternetLayer(server) => {
                let mut events = Events::with_capacity(128);
                if let Some(poller) = &mut self.poller {
                    info!(
                        logger,
                        "Starting to wait for events to happen on the server socket."
                    );
                    poller
                        .poll(&mut events, Some(time::Duration::from_secs(5)))
                        .map_err(ConnectionGeneratorError::IoError)?;
                    info!(logger, "Done waiting for events to happen on the server socket -- something(s) happened (or we timed out).");
                } else {
                    info!(logger, "A poller is not configured for the server socket; assuming that the socket is readable.")
                }

                // We take the completion of `poller.poll` as an indication that the socket is readable.
                // Because it the server socket is the only source in the registry and the socket's change
                // to readable is the only change in which we are `Interest`-ed, it is a safe assumption.
                // It also makes it possible for this code to work whether or not the user has configured
                // polling support.

                let mut buffer = [0u8; 2500];

                let mut cmsg_buffer = server.get_cmsg_buffer();

                let server = server.socket.lock().unwrap();
                let mut iov = [IoSliceMut::new(&mut buffer)];
                match recvmsg::<SockaddrStorage>(
                    server.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg_buffer),
                    MsgFlags::empty(),
                ) {
                    Ok(result) => {
                        info!(
                            logger,
                            "Read {} bytes from the server socket.", result.bytes
                        );

                        if result.iovs().nth(0).is_none() {
                            warn!(logger, "Received a connection but no bytes in the body!");
                            return Err(ConnectionGeneratorError::IoError(
                                std::io::ErrorKind::WriteZero.into(),
                            ));
                        }

                        let client_ip = to_socketaddr(result.address.unwrap());
                        let mut dscp_recv: Option<u8> = None;
                        let mut ttl_recv: Option<i32> = None;
                        let mut traffic_class: Option<i32> = None;
                        let mut ext_headers: Vec<ExtensionHeader> = vec![];

                        match result.cmsgs() {
                            Ok(cmsgs) => {
                                for c in cmsgs {
                                    match c {
                                        ControlMessageOwned::Ipv4Tos(val) => dscp_recv = Some(val),
                                        #[cfg(target_os = "linux")]
                                        ControlMessageOwned::Ipv4Ttl(val) => ttl_recv = Some(val),
                                        #[cfg(target_os = "freebsd")]
                                        ControlMessageOwned::Ipv4Ttl(val) => {
                                            ttl_recv = Some(val.into())
                                        }
                                        ControlMessageOwned::Ipv6TClass(val) => {
                                            traffic_class = Some(val)
                                        }
                                        ControlMessageOwned::Ipv6HopLimit(val) => {
                                            ttl_recv = Some(val)
                                        }
                                        ControlMessageOwned::Ipv6ExtHeader(header) => {
                                            ext_headers.push(ExtensionHeader::Six(header))
                                        }
                                        _ => {
                                            unreachable!()
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    logger,
                                    "Could not get cmsg information for connection: {}", e
                                );
                            }
                        }

                        if dscp_recv.is_none() && ttl_recv.is_none() && traffic_class.is_none() {
                            warn!(logger, "No cmsg information available!\n");
                            //return Err(ConnectionGeneratorError::ExtractionError);
                        }

                        let ttl_recv =
                            TryInto::<u8>::try_into(ttl_recv.unwrap_or(0x0)).map_err(|e| {
                                error!(
                                logger,
                                "There was an error extracting the TTL received from network: {}",
                                e
                            );
                                ConnectionGeneratorError::ExtractionError
                            })?;
                        let dscp_recv =
                            traffic_class.unwrap_or(dscp_recv.unwrap_or_default().into()) as u8;
                        let dscp_value = TryInto::<DscpValue>::try_into(dscp_recv >> 2).unwrap();
                        let ecn_value = Into::<EcnValue>::into(dscp_recv & 0x3);
                        let mode = match (client_ip.ip(), server_socket_addr.ip()) {
                            (IpAddr::V4(_), IpAddr::V4(_)) => IpVersion::Four,
                            (IpAddr::V6(_), IpAddr::V6(_)) => IpVersion::Six,
                            _ => {
                                error!(
                                logger,
                                "There was an invalid IP version combination on the client connection.");
                                return Err(ConnectionGeneratorError::IoError(
                                    ErrorKind::AddrNotAvailable.into(),
                                ));
                            }
                        };

                        let ci = NetworkOptions {
                            mode,
                            ttl: ttl_recv,
                            dscp: dscp_value,
                            ecn: ecn_value,
                            extension_headers: Some(ext_headers),
                        };
                        Ok(Connection {
                            information: ConnectionInformation {
                                ethernet: None,
                                raw_network: None,
                                network: ci,
                            },
                            body: result.iovs().nth(0).unwrap().to_vec(),
                            addr: client_ip,
                        })
                    }
                    Err(Errno::EWOULDBLOCK) => Err(ConnectionGeneratorError::WouldBlock),
                    Err(e) => Err(ConnectionGeneratorError::IoError(e.into())),
                }
            }
        }
    }
}
