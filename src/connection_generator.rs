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
    net::{IpAddr, SocketAddr},
};

use either::Either;
use etherparse::{
    Ethernet2Header, Ipv4Header, Ipv6Header, LinkSlice, NetSlice, SlicedPacket, TransportSlice,
    UdpHeader,
};
use pnet::datalink::DataLinkReceiver;
use slog::trace;

#[derive(Debug)]
pub enum ConnectionGeneratorError {
    Filtered,
    ExtractionError,
    IoError(std::io::Error),
}

pub struct ConnectionGenerator<'a> {
    connection: Either<Box<dyn DataLinkReceiver>, &'a mut SocketAddr>,
}

impl From<Box<dyn DataLinkReceiver>> for ConnectionGenerator<'_> {
    fn from(value: Box<dyn DataLinkReceiver>) -> Self {
        Self {
            connection: either::Left(value),
        }
    }
}

pub type Connection = (Option<Ethernet2Header>, IpHeaders, Vec<u8>, SocketAddr);
pub type IpHeaders = either::Either<Ipv4Header, Ipv6Header>;

impl ConnectionGenerator<'_> {
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
                    Some(NetSlice::Ipv6(ipv6)) => either::Right(ipv6.header().to_header().clone()),
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
                todo!("Implement Ipv6 support for packet filtering")
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
        bind_socket_addr: SocketAddr,
    ) -> Result<Connection, ConnectionGeneratorError> {
        match &mut self.connection {
            Either::Left(interface) => match interface.next() {
                Ok(pkt) => {
                    if let Some((ethernet_pkt, ip_pkt_hdr, udp_header, udp_bytes)) =
                        Self::extract_packets(pkt)
                    {
                        if !Self::packet_filter(
                            &ip_pkt_hdr,
                            &udp_header,
                            bind_socket_addr,
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
            Either::Right(_) => {
                todo!("Implement Connection Generator for 'regular' socket.")
            }
        }
    }
}
