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
    io::{Error, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    time,
};

use either::Either::{Left, Right};
use etherparse::{
    ip_number::UDP, Ethernet2Header, IpNumber, Ipv4Dscp, Ipv4Ecn, Ipv4Header, Ipv6Header,
    LinkSlice, NetSlice, SlicedPacket, TransportSlice, UdpHeader,
};
use mio::{Events, Interest};
use nix::{
    errno::Errno,
    sys::socket::{recvmsg, ControlMessageOwned, Ipv6ExtHeader, MsgFlags, SockaddrStorage},
};
use pnet::datalink::DataLinkReceiver;
use slog::{error, info, trace, warn};

use crate::{server::ServerSocket, util::to_socketaddr};

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
pub type Connection = (Option<Ethernet2Header>, IpHeaders, Vec<u8>, SocketAddr);
pub type IpHeaders = either::Either<Ipv4Header, ExtendedIpv6Header>;

impl ConnectionGenerator {
    fn extract_packets(pkt: &[u8]) -> Option<(Ethernet2Header, IpHeaders, UdpHeader, Vec<u8>)> {
        match SlicedPacket::from_ethernet(pkt) {
            Ok(pieces) => {
                let link_header = if let Some(LinkSlice::Ethernet2(ether)) = pieces.link {
                    ether.to_header().clone()
                } else {
                    return None;
                };

                let net_header = match pieces.net {
                    Some(NetSlice::Ipv4(ipv4)) => either::Left(ipv4.header().to_header().clone()),
                    Some(NetSlice::Ipv6(ipv6)) => {
                        either::Right((ipv6.header().to_header().clone(), vec![]))
                    }
                    _ => {
                        return None;
                    }
                };
                let (transport_header, transport_bytes) =
                    if let Some(TransportSlice::Udp(udp)) = pieces.transport {
                        (udp.to_header(), udp.payload().to_vec())
                    } else {
                        return None;
                    };
                Some((link_header, net_header, transport_header, transport_bytes))
            }
            Err(_) => None,
        }
    }

    fn packet_filter(
        ip_pkt_hdr: &IpHeaders,
        udp_pkt_hdr: &UdpHeader,
        address: SocketAddr,
        logger: slog::Logger,
    ) -> bool {
        match ip_pkt_hdr {
            IpHeaders::Left(ipv4) => {
                if !address.ip().is_unspecified()
                    && Into::<IpAddr>::into(ipv4.destination) != address.ip()
                {
                    trace!(
                        logger,
                        "Got a udp packet that was not for our IP (expected {}, got {}). Skipping",
                        Into::<IpAddr>::into(ipv4.destination),
                        address.ip()
                    );
                    return false;
                }
            }
            IpHeaders::Right(_) => {
                trace!(
                    logger,
                    "Packet filtering for Ipv6 is not yet implemented. Skipping."
                );
                return false;
            }
        }
        if udp_pkt_hdr.destination_port != address.port() {
            trace!(
                logger,
                "Got a udp packet that was not for our port ({}). Skipping",
                udp_pkt_hdr.destination_port
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
                    if let Some((ethernet_pkt, ip_pkt_hdr, udp_header, udp_bytes)) =
                        Self::extract_packets(pkt)
                    {
                        if !Self::packet_filter(
                            &ip_pkt_hdr,
                            &udp_header,
                            server_socket_addr,
                            logger.clone(),
                        ) {
                            trace!(
                                logger,
                                "Skipping a received packet because it was filtered."
                            );
                            return Err(ConnectionGeneratorError::Filtered);
                        }

                        let client_address: SocketAddr = match &ip_pkt_hdr {
                            IpHeaders::Left(ipv4) => {
                                (Into::<IpAddr>::into(ipv4.source), udp_header.source_port).into()
                            }
                            IpHeaders::Right(_) => {
                                todo!(
                                    "Implement Ipv6 support for calculating the client IP address"
                                )
                            }
                        };

                        Ok((Some(ethernet_pkt), ip_pkt_hdr, udp_bytes, client_address))
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

                        let client_ip = to_socketaddr(result.address.unwrap());
                        let mut dscp_recv: Option<u8> = None;
                        let mut ttl_recv: Option<i32> = None;
                        let mut traffic_class: Option<i32> = None;
                        let mut ext_headers: Vec<Ipv6ExtHeader> = vec![];

                        match result.cmsgs() {
                            Ok(cmsgs) => {
                                for c in cmsgs {
                                    match c {
                                        ControlMessageOwned::Ipv4Tos(val) => dscp_recv = Some(val),
                                        ControlMessageOwned::Ipv4Ttl(val) => ttl_recv = Some(val),
                                        ControlMessageOwned::Ipv6TClass(val) => {
                                            traffic_class = Some(val)
                                        }
                                        ControlMessageOwned::Ipv6HopLimit(val) => {
                                            ttl_recv = Some(val)
                                        }
                                        ControlMessageOwned::Ipv6ExtHeader(header) => {
                                            ext_headers.push(header)
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
                        let dscp_recv = dscp_recv.unwrap_or(0x0);
                        let ip_hdr = match (client_ip.ip(), server_socket_addr.ip()) {
                            (IpAddr::V4(cv4), IpAddr::V4(sv4)) => either::Left(
                                Ipv4Header::new(
                                    500,
                                    ttl_recv,
                                    IpNumber::UDP,
                                    cv4.octets(),
                                    sv4.octets(),
                                )
                                .unwrap(),
                            ),
                            (IpAddr::V6(cv6), IpAddr::V6(sv6)) => either::Right(Ipv6Header {
                                payload_length: 500,
                                hop_limit: ttl_recv,
                                traffic_class: traffic_class.unwrap_or(0x0) as u8,
                                flow_label: Default::default(),
                                next_header: UDP,
                                source: cv6.octets(),
                                destination: sv6.octets(),
                            }),
                            _ => {
                                error!(
                                    logger,
                                    "There was an unrecognized client/server protocol combination."
                                );
                                return Err(ConnectionGeneratorError::IoError(Error::other(
                                    "Unrecognized client/server protocol combination.",
                                )));
                            }
                        };

                        match ip_hdr {
                            Left(mut ip_hdr) => {
                                ip_hdr.dscp = Ipv4Dscp::try_new(dscp_recv >> 2).unwrap();
                                ip_hdr.ecn = Ipv4Ecn::try_new(dscp_recv & 0x3).unwrap();
                                Ok((
                                    None,
                                    either::Left(ip_hdr),
                                    result.iovs().nth(0).unwrap().to_vec(),
                                    client_ip,
                                ))
                            }
                            Right(ip6_hdr) => Ok((
                                None,
                                either::Right((ip6_hdr, ext_headers)),
                                result.iovs().nth(0).unwrap().to_vec(),
                                client_ip,
                            )),
                        }
                    }
                    Err(Errno::EWOULDBLOCK) => Err(ConnectionGeneratorError::WouldBlock),
                    Err(e) => Err(ConnectionGeneratorError::IoError(e.into())),
                }
            }
        }
    }
}
