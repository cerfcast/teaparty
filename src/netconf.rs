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
