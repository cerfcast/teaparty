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

use std::fmt::{Debug, Display};
use std::net::UdpSocket;

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
    MaxParameterKind = 4,
}

#[derive(Clone, Debug)]
pub struct NetConfiguration {
    configurations: Vec<(NetConfigurationItem, u8)>,
}

impl NetConfiguration {
    pub fn new() -> Self {
        NetConfiguration {
            configurations: [(NetConfigurationItem::Invalid, 0);
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
    pub fn configure(
        &self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        handlers: Handlers,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        for (configuration, setter) in &self.configurations {
            let configuration_result = match configuration {
                NetConfigurationItem::Dscp(value) => {
                    info!(logger, "Configuring a DSCP value via net configuration.");
                    let existing_ecn_value = match Ipv4Tos.get(&socket) {
                        Ok(v) => v & 0x03, // Make sure that we only keep the ECN from the existing TOS value.
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            0
                        }
                    };

                    let raw_dscp_value = Into::<u8>::into(*value) as i32 | existing_ecn_value;
                    if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &raw_dscp_value) {
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
                        Ok(())
                    }
                }
                NetConfigurationItem::Ecn(value) => {
                    info!(logger, "Configuring an ECN value via net configuration.");
                    let existing_dscp_value = match Ipv4Tos.get(&socket) {
                        Ok(v) => v & 0xfc, // Make sure that we only keep the ECN from the existing TOS value.
                        Err(e) => {
                            error!(
                                logger,
                                "There was an error getting the existing TOS values when attempting to do a net configuration: {}; assuming it was empty!",
                                e
                            );
                            0
                        }
                    };

                    let raw_tos_value = Into::<u8>::into(*value) as i32 | existing_dscp_value;
                    if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &raw_tos_value) {
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
                        Ok(())
                    }
                }
                NetConfigurationItem::Ttl(_value) => {
                    todo!()
                }
                NetConfigurationItem::Invalid => Ok(()),
            };

            if let Err(e) = configuration_result {
                let erring_handler = handlers.get_handler(*setter).unwrap();
                let erring_handler = erring_handler.lock().unwrap();

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
            }
        }
        Ok(())
    }
}
