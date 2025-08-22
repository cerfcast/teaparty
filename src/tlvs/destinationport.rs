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

use std::net::{SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    handlers::{
        TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator,
        TlvRequestResult, TlvSenderHandler, TlvSenderHandlerConfigurator,
    },
    netconf::NetConfigurator,
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

#[derive(Default, Debug)]
pub struct DestinationPortTlv {
    pub port: u16,
}

impl TryFrom<&Tlv> for DestinationPortTlv {
    type Error = StampError;
    fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
        if value.length != 4 {
            return Err(StampError::MalformedTlv(Error::NotEnoughData));
        }
        let port: u16 = u16::from_be_bytes(value.value[0..2].try_into().map_err(|_| {
            StampError::MalformedTlv(Error::FieldValueInvalid(
                "Could not extract port number from TLV value.".to_string(),
            ))
        })?);
        Ok(Self { port })
    }
}

#[derive(Subcommand, Clone, Debug)]
enum DestinationPortTlvCommand {
    DestinationPort {
        #[arg(long, default_value_t = 863)]
        port: u16,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}
impl TlvReflectorHandler for DestinationPortTlv {
    fn tlv_name(&self) -> String {
        "Destination Port".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::DESTINATION_PORT].to_vec()
    }

    fn handle(
        &mut self,
        tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        _session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am handling a destination port Tlv.");

        let mut result_tlv = tlv.clone();
        result_tlv.flags.set_unrecognized(false);

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
            "Preparing the response target in the destination port Tlv."
        );
        for tlv in response.tlvs.tlvs.iter() {
            if self.tlv_sender_type().contains(&tlv.tpe) {
                let new_port: u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                let mut ipv4 = source_address;
                ipv4.set_port(new_port);
                return (source_address, ipv4);
            }
        }
        (source_address, destination_address)
    }
}

impl NetConfigurator for DestinationPortTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Destination Port) that does not set net configuration items.");
    }
}

impl TlvSenderHandler for DestinationPortTlv {
    fn tlv_name(&self) -> String {
        "Destination Port".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        DestinationPortTlvCommand::augment_subcommands(existing)
    }
    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::DESTINATION_PORT].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
        let maybe_our_command = DestinationPortTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let DestinationPortTlvCommand::DestinationPort {
            port,
            next_tlv_command,
        } = our_command;
        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        let mut data = [0u8; 4];

        data[0..2].copy_from_slice(&port.to_be_bytes());

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::DESTINATION_PORT,
                length: 4,
                value: data.to_vec(),
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

impl TlvSenderHandlerConfigurator for DestinationPortTlv {}
impl TlvReflectorHandlerConfigurator for DestinationPortTlv {}
pub struct DestinationPortTlvReflectorConfig {}

impl TlvHandlerGenerator for DestinationPortTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "destination-port".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(DestinationPortTlv::default())
    }
}
