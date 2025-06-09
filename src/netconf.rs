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
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};

use nix::sys::socket::sockopt::{Ipv4Ttl, Ipv6TClass, Ipv6Ttl};
use nix::sys::socket::{sockopt::Ipv4Tos, GetSockOpt, SetSockOpt};
use nix::sys::socket::{ControlMessageOwned, Ipv6ExtHeader};
use slog::Logger;
use slog::{error, info};

use crate::handlers::Handlers;
use crate::ip::{DscpValue, EcnValue};
use crate::stamp::StampMsg;
use crate::tlv::Tlv;

#[allow(dead_code)]
#[derive(Debug)]
pub enum NetConfigurationError {
    CouldNotSet(String, std::io::Error),
}
impl Display for NetConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum NetConfigurationArgument {
    Ttl(u8),
    Ecn(EcnValue),
    Dscp(DscpValue),
    ExtensionHeader(Ipv6ExtHeader),
    Invalid,
}

pub trait NetConfigurationItemT: Display {
    fn set(&mut self, arg: NetConfigurationArgument) -> Result<(), NetConfigurationError>;
    fn get(&mut self) -> NetConfigurationItem;
    fn configure(
        &mut self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError>;
    fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError>;
    fn get_cmsg(&self) -> Vec<ControlMessageOwned> {
        vec![]
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub enum NetConfigurationItem {
    Ttl(u8),
    Ecn(EcnValue),
    Dscp(DscpValue),
    ExtensionHeader(Ipv6ExtHeader),
    Invalid,
}

impl Default for NetConfigurationItem {
    fn default() -> Self {
        Self::Invalid
    }
}

pub struct ExtensionHeaderNetConfigurationItem {
    values: Vec<Ipv6ExtHeader>,
}

impl Display for ExtensionHeaderNetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Extension Header")
    }
}

impl NetConfigurationItemT for ExtensionHeaderNetConfigurationItem {
    fn get(&mut self) -> NetConfigurationItem {
        todo!()
    }

    fn get_cmsg(&self) -> Vec<ControlMessageOwned> {
        self.values
            .iter()
            .map(|f| ControlMessageOwned::Ipv6ExtHeader(f.clone()))
            .collect()
    }

    fn set(&mut self, arg: NetConfigurationArgument) -> Result<(), NetConfigurationError> {
        match arg {
            NetConfigurationArgument::ExtensionHeader(header) => {
                self.values.push(header);
                Ok(())
            }
            _ => Err(NetConfigurationError::CouldNotSet(
                "Extension Header".to_string(),
                ErrorKind::InvalidData.into(),
            )),
        }
    }

    fn configure(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        Ok(())
    }

    fn unconfigure(
        &mut self,
        _socket: &UdpSocket,
        _logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        Ok(())
    }
}

pub struct TtlNetConfigurationItem {
    orig: u8,
    value: u8,
}

impl Display for TtlNetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TTL")
    }
}

impl TtlNetConfigurationItem {
    fn swap_value_on_socket(
        value: u8,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<u8, NetConfigurationError> {
        info!(logger, "Configuring a TTL value via net configuration.");
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
                            "There was an error getting the TTL value of the reflected packet via net configuration: {}", e
                        );
                return Err(NetConfigurationError::CouldNotSet(
                    "TTL".to_string(),
                    std::io::Error::other(e.desc()),
                ));
            }
        };

        let settable_ttl = value as i32;
        if let Err(set_ttl_value_err) = if is_ipv4 {
            Ipv4Ttl.set(&socket, &settable_ttl)
        } else {
            Ipv6Ttl.set(&socket, &settable_ttl)
        } {
            error!(
                            logger,
                            "There was an error setting the TTL value of the reflected packet via net configuration: {}",
                            set_ttl_value_err
                        );
            Err(NetConfigurationError::CouldNotSet(
                "TTL".to_string(),
                std::io::Error::other(set_ttl_value_err.desc()),
            ))
        } else {
            Ok(original_ttl as u8)
        }
    }
}

impl NetConfigurationItemT for TtlNetConfigurationItem {
    fn get(&mut self) -> NetConfigurationItem {
        NetConfigurationItem::Ttl(self.value)
    }

    fn set(&mut self, arg: NetConfigurationArgument) -> Result<(), NetConfigurationError> {
        match arg {
            NetConfigurationArgument::Ttl(b) => {
                self.value = b;
                Ok(())
            }
            _ => Err(NetConfigurationError::CouldNotSet(
                "TTL".to_string(),
                ErrorKind::InvalidInput.into(),
            )),
        }
    }

    fn configure(
        &mut self,
        _response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match TtlNetConfigurationItem::swap_value_on_socket(self.value, socket, logger) {
            Ok(orig) => {
                self.orig = orig;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match TtlNetConfigurationItem::swap_value_on_socket(self.orig, socket, logger) {
            Ok(_) => {
                self.orig = 0;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

pub struct DscpNetConfigurationItem {
    orig: u8,
    value: u8,
}

impl Display for DscpNetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DSCP")
    }
}

impl DscpNetConfigurationItem {
    fn swap_value_on_socket(
        value: u8,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<u8, NetConfigurationError> {
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

        let raw_dscp_value = Into::<u8>::into(value) | existing_ecn_value;
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
                "DSCP".to_string(),
                std::io::Error::other(set_tos_value_err.desc()),
            ))
        } else {
            Ok(orig)
        }
    }
}

impl NetConfigurationItemT for DscpNetConfigurationItem {
    fn get(&mut self) -> NetConfigurationItem {
        NetConfigurationItem::Dscp(TryInto::<DscpValue>::try_into(self.value).unwrap())
    }
    fn set(&mut self, arg: NetConfigurationArgument) -> Result<(), NetConfigurationError> {
        match arg {
            NetConfigurationArgument::Dscp(b) => {
                self.value = b.into();
                Ok(())
            }
            _ => Err(NetConfigurationError::CouldNotSet(
                "ECN".to_string(),
                ErrorKind::InvalidInput.into(),
            )),
        }
    }

    fn configure(
        &mut self,
        _response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match DscpNetConfigurationItem::swap_value_on_socket(self.value, socket, logger) {
            Ok(orig) => {
                self.orig = orig;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match DscpNetConfigurationItem::swap_value_on_socket(self.orig, socket, logger) {
            Ok(orig) => {
                self.orig = orig;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

pub struct EcnNetConfigurationItem {
    orig: u8,
    value: u8,
}

impl Display for EcnNetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECN")
    }
}
impl EcnNetConfigurationItem {
    fn swap_value_on_socket(
        value: u8,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<u8, NetConfigurationError> {
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

        let raw_tos_value = value | existing_dscp_value;
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
                "ECN".to_string(),
                std::io::Error::other(set_tos_value_err.desc()),
            ))
        } else {
            Ok(orig)
        }
    }
}

impl NetConfigurationItemT for EcnNetConfigurationItem {
    fn get(&mut self) -> NetConfigurationItem {
        NetConfigurationItem::Ecn(Into::<EcnValue>::into(self.value))
    }

    fn set(&mut self, arg: NetConfigurationArgument) -> Result<(), NetConfigurationError> {
        match arg {
            NetConfigurationArgument::Ecn(b) => {
                self.value = b.into();
                Ok(())
            }
            _ => Err(NetConfigurationError::CouldNotSet(
                "ECN".to_string(),
                ErrorKind::InvalidInput.into(),
            )),
        }
    }

    fn configure(
        &mut self,
        _response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match EcnNetConfigurationItem::swap_value_on_socket(self.value, socket, logger) {
            Ok(orig) => {
                self.orig = orig;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        match EcnNetConfigurationItem::swap_value_on_socket(self.orig, socket, logger) {
            Ok(orig) => {
                self.orig = orig;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Display for NetConfigurationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetConfigurationItem::Ttl(ttl) => write!(f, "TTL = {}", ttl),
            NetConfigurationItem::Ecn(ecn) => write!(f, "ECN = {:?}", ecn),
            NetConfigurationItem::Dscp(value) => write!(f, "Dscp = {:?}", value),
            NetConfigurationItem::ExtensionHeader(_value) => write!(f, "Extension Header"),
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
    ExtensionHeader = 3,
    Invalid = 4,
    MaxParameterKind = 5,
}

#[derive(Clone)]
pub struct NetConfiguration {
    configurations: Vec<Arc<Mutex<dyn NetConfigurationItemT + Send>>>,
    setters: Vec<u8>,
}

impl NetConfiguration {
    pub const CLIENT_SETTER: u8 = 125;
    pub fn new() -> Self {
        NetConfiguration {
            configurations: vec![
                Arc::<Mutex<_>>::new(Mutex::new(TtlNetConfigurationItem { orig: 0, value: 0 })),
                Arc::<Mutex<_>>::new(Mutex::new(EcnNetConfigurationItem { orig: 0, value: 0 })),
                Arc::<Mutex<_>>::new(Mutex::new(DscpNetConfigurationItem { orig: 0, value: 0 })),
                Arc::<Mutex<_>>::new(Mutex::new(ExtensionHeaderNetConfigurationItem {
                    values: vec![],
                })),
            ],
            setters: vec![0u8; 4],
        }
    }
}

impl NetConfiguration {
    pub fn add_configuration(
        &mut self,
        parameter: NetConfigurationItemKind,
        arg: NetConfigurationArgument,
        setter: u8,
    ) {
        if parameter < NetConfigurationItemKind::MaxParameterKind {
            let mut configurator = self.configurations[parameter as usize].lock().unwrap();
            if configurator.set(arg).is_ok() {
                self.setters[parameter as usize] = setter;
            }
        }
    }

    pub fn unconfigure(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        for (configuration, setter) in &mut self
            .configurations
            .iter()
            .zip(self.setters.clone())
            .filter(|(_, setter)| *setter != 0)
        {
            let mut configurator = configuration.lock().unwrap();
            let configuration_result = configurator.unconfigure(socket, logger.clone());

            if let Err(e) = configuration_result {
                error!(
                    logger,
                    "There was a net config error ({}) when unconfiguring {} (set by setter with ID {}).",
                    e, configurator, Tlv::type_to_string(setter)
                );
            }
        }
        Ok(())
    }

    pub fn get_cmsgs(&self) -> Vec<ControlMessageOwned> {
        self.configurations
            .iter()
            .flat_map(|f| f.lock().unwrap().get_cmsg())
            .collect()
    }

    pub fn configure(
        &mut self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        handlers: Option<Handlers>,
        logger: Logger,
    ) -> Result<(), NetConfigurationError> {
        for (configuration, setter) in &mut self
            .configurations
            .iter()
            .zip(self.setters.clone())
            .filter(|(_, setter)| *setter != 0)
        {
            let mut configurator = configuration.lock().unwrap();
            let configuration_result = configurator.configure(response, socket, logger.clone());

            if let Err(e) = configuration_result {
                if let Some(handlers) = &handlers {
                    if let Some(erring_handler) = handlers.get_handler(setter) {
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
                            configurator.get(),
                            logger.clone(),
                        );
                    } else {
                        error!(
                            logger,
                            "There was a net config error ({}) but no handlers are available to respond.", e);
                    }
                } else {
                    error!(
                            logger,
                            "There was a net config error ({}) but no handlers are available to respond.", e);
                }
            }
        }
        Ok(())
    }
}
