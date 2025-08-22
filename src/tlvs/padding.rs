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

use std::net::{SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Flags, Tlv},
};

pub struct PaddingTlv {}

#[derive(Subcommand, Clone, Debug)]
enum PaddingTlvCommand {
    Padding {
        #[arg(short, default_value_t = 64)]
        size: u16,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl TlvReflectorHandler for PaddingTlv {
    fn tlv_name(&self) -> String {
        "Padding".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::PADDING].to_vec()
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
        info!(logger, "Handling the response in the Padding Tlv.");
        let mut response = tlv.clone();
        response.flags = Flags::new_response();
        Ok(response)
    }
    fn pre_send_fixup(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        _logger: Logger,
    ) -> Result<(), StampError> {
        Ok(())
    }
}

impl TlvHandler for PaddingTlv {
    fn handle_netconfig_error(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Padding) that does not set net configuration items.");
    }
}

impl TlvSenderHandler for PaddingTlv {
    fn tlv_name(&self) -> String {
        "Padding".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        PaddingTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::PADDING].to_vec()
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = PaddingTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let PaddingTlvCommand::Padding {
            size,
            next_tlv_command,
        } = our_command;
        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::PADDING,
                length: size,
                value: vec![0u8; size as usize],
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }

    fn pre_send_fixup(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        _logger: Logger,
    ) -> Result<(), StampError> {
        Ok(())
    }
}

pub struct PaddingTlvReflectorConfig {}

impl TlvHandlerGenerator for PaddingTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "padding".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandler + Send> {
        Box::new(PaddingTlv {})
    }
}
