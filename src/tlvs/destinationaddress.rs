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

use crate::handlers::{TlvHandler, TlvHandlerGenerator, TlvReflectorHandler};

use std::net::{IpAddr, SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{Ssid, StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

#[derive(Default, Debug)]
pub struct DestinationAddressTlv {
    pub address: Option<IpAddr>,
}

impl TryFrom<&Tlv> for DestinationAddressTlv {
    type Error = StampError;
    fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
        if !(value.length == 4 || value.length == 16) {
            return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                "Length must be either 4 or 16".to_string(),
            )));
        }
        let address = if value.length == 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value.value.as_slice()[0..4]);
            Into::<IpAddr>::into(bytes)
        } else {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value.value.as_slice()[0..16]);
            Into::<IpAddr>::into(bytes)
        };
        Ok(Self {
            address: Some(address),
        })
    }
}

#[derive(Subcommand, Clone, Debug)]
enum DestinationAddressTlvCommand {
    DestinationAddress {
        #[arg(long)]
        address: IpAddr,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}
impl TlvReflectorHandler for DestinationAddressTlv {
    fn tlv_name(&self) -> String {
        "Destination Address".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::DESTINATION_ADDRESS].to_vec()
    }

    fn handle(
        &mut self,
        tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am handling a destination address Tlv.");

        let has_ssid = session
            .as_ref()
            .map(|session| match session.ssid.clone() {
                Ssid::Mbz(_) => false,
                Ssid::Ssid(v) => v != 0,
            })
            .unwrap_or(false);

        // When there is a destination address TLV there must be an SSID.
        if !has_ssid {
            return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                "Ssid".to_string(),
            )));
        }

        let destination_tlv = TryInto::<DestinationAddressTlv>::try_into(tlv)?;

        // Make sure that the destination address is of the same address family.
        self.address = destination_tlv.address.filter(|addr| {
            if _client.is_ipv4() && addr.is_ipv4() {
                true
            } else if _client.is_ipv6() && addr.is_ipv6() {
                // Yes, redundant; write for clarity.
                true
            } else {
                false
            }
        });

        let mut result_tlv = tlv.clone();

        // If there is no destination address, then the response should be unrecognized.
        result_tlv.flags.set_unrecognized(self.address.is_none());

        Ok(result_tlv)
    }

    fn prepare_response_addrs(
        &mut self,
        response: &mut StampMsg,
        source_address: SocketAddr,
        destination_address: SocketAddr,
        logger: Logger,
    ) -> (SocketAddr, SocketAddr) {
        info!(
                logger,
                "Preparing the response source in the destination address Tlv by changing the source address."
            );

        if self.address.is_none() {
            return (source_address, destination_address);
        }
        let new_source_address = self.address.unwrap();

        for tlv in response.tlvs.tlvs.iter() {
            if self.tlv_sender_type().contains(&tlv.tpe) {
                let port = source_address.port();
                return (
                    SocketAddr::new(new_source_address, port),
                    destination_address,
                );
            }
        }
        (source_address, destination_address)
    }
}

impl TlvHandler for DestinationAddressTlv {
    fn handle_netconfig_error(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Destination Address) that does not set net configuration items.");
    }
}
impl TlvSenderHandler for DestinationAddressTlv {
    fn tlv_name(&self) -> String {
        "Destination Address".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        DestinationAddressTlvCommand::augment_subcommands(existing)
    }
    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::DESTINATION_ADDRESS].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
        let maybe_our_command = DestinationAddressTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let DestinationAddressTlvCommand::DestinationAddress {
            address,
            next_tlv_command,
        } = our_command;
        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        let value = match address {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::DESTINATION_ADDRESS,
                length: value.len() as u16,
                value,
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

pub struct DestinationAddressTlvReflectorConfig {}

impl TlvHandlerGenerator for DestinationAddressTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "destination-address".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandler + Send> {
        Box::new(DestinationAddressTlv::default())
    }
}
