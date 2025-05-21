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

use std::fmt::{Debug, Display};
use std::net::UdpSocket;

use nix::sys::socket::sockopt::{Ipv4Ttl, Ipv6TClass, Ipv6Ttl};
use nix::sys::socket::{sockopt::Ipv4Tos, GetSockOpt, SetSockOpt};
use slog::Logger;
use slog::{error, info};

use crate::handlers::Handlers;
use crate::ip::{DscpValue, EcnValue};
use crate::stamp::StampMsg;

#[allow(dead_code)]
#[derive(Debug)]
pub enum NetConfigurationError {
    CouldNotSet(NetConfigurationItem, std::io::Error),
}
impl Display for NetConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum NetConfigurationItem {
    Ttl(u8),
    Ecn(EcnValue),
    Dscp(DscpValue),
    Invalid,
}

impl Default for NetConfigurationItem {
    fn default() -> Self {
        Self::Invalid
    }
}

impl Display for NetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetConfigurationItem::Ttl(ttl) => write!(f, "TTL = {}", ttl),
            NetConfigurationItem::Ecn(ecn) => write!(f, "ECN = {:?}", ecn),
            NetConfigurationItem::Dscp(value) => write!(f, "Dscp = {:?}", value),
            NetConfigurationItem::Invalid => write!(f, "Invalid."),
        }
    }
}

impl Debug for NetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(PartialEq, PartialOrd, Debug, Clone, Copy)]
#[repr(usize)]
#[allow(dead_code)]
pub enum NetConfigurationItemKind {
    Ttl = 0,
    Ecn = 1,
    Dscp = 2,
    Invalid = 3,
    MaxParameterKind = 4,
}

#[derive(Clone, Debug)]
pub struct NetConfiguration {
    configurations: Vec<(NetConfigurationItem, u8)>,
    originals: Vec<NetConfigurationItem>,
}

impl NetConfiguration {
    pub fn new() -> Self {
        NetConfiguration {
            configurations: [(NetConfigurationItem::Invalid, 0);
                NetConfigurationItemKind::MaxParameterKind as usize]
                .to_vec(),
            originals: [(NetConfigurationItem::Invalid);
                NetConfigurationItemKind::MaxParameterKind as usize]
                .to_vec(),
        }
    }
}

impl NetConfiguration {
    pub fn add_configuration(
        &mut self,
        parameter: NetConfigurationItemKind,
        arg: NetConfigurationItem,
        setter: u8,
    ) {
        if parameter < NetConfigurationItemKind::MaxParameterKind {
            self.configurations[parameter as usize] = (arg, setter);
        }
    }

    pub fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        for configuration in &mut self.originals {
            Self::configure_one(configuration, socket, &logger)?;
        }
        Ok(())
    }

    pub fn configure(
        &mut self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        handlers: Option<Handlers>,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        for (configuration, setter) in &mut self.configurations {
            let configuration_result = Self::configure_one(configuration, socket, &logger);

            match configuration_result {
                Ok((orig_type, orig_value)) => self.originals[orig_type as usize] = orig_value,
                Err(e) => {
                    if let Some(handlers) = &handlers {
                        let erring_handler = handlers.get_handler(*setter).unwrap();
                        let mut erring_handler = erring_handler.lock().unwrap();

                        error!(
                            logger,
                            "Asking {} to handle a net configuration error: {}",
                            erring_handler.tlv_name(),
                            e
                        );
                        erring_handler.handle_netconfig_error(
                            response,
                            socket,
                            *configuration,
                            logger.clone(),
                        );
                    } else {
                        error!(
                            logger,
                            "There was a net config error ({}) but no handlers are available to respond.", e);
                    }
                }
            }
        }
        Ok(())
    }

    fn configure_one(
        configuration: &NetConfigurationItem,
        socket: &UdpSocket,
        logger: &Logger,
    ) -> Result<(NetConfigurationItemKind, NetConfigurationItem), NetConfigurationError> {
        match configuration {
            // DSCP
            NetConfigurationItem::Dscp(value) => {
                info!(logger, "Configuring a DSCP value via net configuration.");

                let is_ipv4 = socket.local_addr().unwrap().is_ipv4();

                let (orig, existing_ecn_value) = if is_ipv4 {
                    match Ipv4Tos.get(&socket) {
                        Ok(v) => ((v & 0xfc) as u8, (v & 0x03) as u8),
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            (0, 0)
                        }
                    }
                } else {
                    match Ipv6TClass.get(&socket) {
                        Ok(v) => ((v & 0xfc) as u8, (v & 0x03) as u8), // Make sure that we only keep the ECN from the existing TOS value.
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values (IPv6) when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            (0, 0)
                        }
                    }
                };

                let raw_dscp_value = Into::<u8>::into(*value) | existing_ecn_value;
                if let Err(set_tos_value_err) = if is_ipv4 {
                    Ipv4Tos.set(&socket, &(raw_dscp_value as i32))
                } else {
                    Ipv6TClass.set(&socket, &(raw_dscp_value as i32))
                } {
                    error!(
                            logger,
                            "There was an error setting the DSCP value of the reflected packet via net configuration: {}",
                            set_tos_value_err
                        );
                    Err(NetConfigurationError::CouldNotSet(
                        *configuration,
                        std::io::Error::other(set_tos_value_err.desc()),
                    ))
                } else {
                    match (orig >> 2).try_into() {
                        Ok(dscp) => Ok((
                            NetConfigurationItemKind::Dscp,
                            // Don't forget to shift right -- into assumes that this is the case for DSCP values.
                            NetConfigurationItem::Dscp(dscp),
                        )),
                        Err(e) => Err(NetConfigurationError::CouldNotSet(
                            *configuration,
                            std::io::Error::other(e),
                        )),
                    }
                }
            }
            // ECN
            NetConfigurationItem::Ecn(value) => {
                info!(logger, "Configuring an ECN value via net configuration.");

                let is_ipv4 = socket.local_addr().unwrap().is_ipv4();

                let (existing_dscp_value, orig) = if is_ipv4 {
                    match Ipv4Tos.get(&socket) {
                        Ok(v) => ((v & 0xfc) as u8, (v & 0x03) as u8), // Make sure that we only keep the ECN from the existing TOS value.
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            (0, 0)
                        }
                    }
                } else {
                    match Ipv6TClass.get(&socket) {
                        Ok(v) => ((v & 0xfc) as u8, (v & 0x03) as u8), // Make sure that we only keep the ECN from the existing TOS value.
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values (IPv6) when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            (0, 0)
                        }
                    }
                };

                let raw_tos_value = Into::<u8>::into(*value) | existing_dscp_value;
                if let Err(set_tos_value_err) = if is_ipv4 {
                    Ipv4Tos.set(&socket, &(raw_tos_value as i32))
                } else {
                    Ipv6TClass.set(&socket, &(raw_tos_value as i32))
                } {
                    error!(
                            logger,
                            "There was an error setting the ECN value of the reflected packet via net configuration: {}",
                            set_tos_value_err
                        );
                    Err(NetConfigurationError::CouldNotSet(
                        *configuration,
                        std::io::Error::other(set_tos_value_err.desc()),
                    ))
                } else {
                    Ok((
                        NetConfigurationItemKind::Ecn,
                        NetConfigurationItem::Ecn(orig.into()),
                    ))
                }
            }
            // TTL
            NetConfigurationItem::Ttl(value) => {
                let is_ipv4 = socket.local_addr().unwrap().is_ipv4();

                let original_ttl = match if is_ipv4 {
                    Ipv4Ttl.get(&socket)
                } else {
                    Ipv6Ttl.get(&socket)
                } {
                    Ok(orig) => orig,
                    Err(e) => {
                        error!(
                            logger,
                            "There was an error setting the TTL value of the reflected packet via net configuration: {}", e
                        );
                        return Err(NetConfigurationError::CouldNotSet(
                            *configuration,
                            std::io::Error::other(e.desc()),
                        ));
                    }
                };

                let settable_ttl = *value as i32;
                if let Err(set_ttl_value_err) = if is_ipv4 {
                    Ipv4Ttl.set(&socket, &settable_ttl)
                } else {
                    Ipv6TClass.set(&socket, &settable_ttl)
                } {
                    error!(
                            logger,
                            "There was an error setting the TTL value of the reflected packet via net configuration: {}",
                            set_ttl_value_err
                        );
                    Err(NetConfigurationError::CouldNotSet(
                        *configuration,
                        std::io::Error::other(set_ttl_value_err.desc()),
                    ))
                } else {
                    Ok((
                        NetConfigurationItemKind::Ttl,
                        NetConfigurationItem::Ttl(original_ttl as u8),
                    ))
                }
            }
            NetConfigurationItem::Invalid => Ok((
                NetConfigurationItemKind::Invalid,
                NetConfigurationItem::Invalid,
            )),
        }
    }
}
