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
    netconf::{NetConfiguration, NetConfigurationItem, NetConfigurator},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Flags, Tlv},
};

pub struct TimeTlv {}

#[derive(Subcommand, Clone, Debug)]
enum TimeTlvCommand {
    Time {
        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl TlvReflectorHandler for TimeTlv {
    fn tlv_name(&self) -> String {
        "Time".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::TIMESTAMP].to_vec()
    }

    fn handle(
        &mut self,
        _tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        _session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am handling a timestamp Tlv.");
        let mut response_data = [0u8; 4];
        response_data[0] = 1; // NTP
        response_data[1] = 2; // Software local
        response_data[2] = 1; // NTP
        response_data[3] = 2; // Software local
        let response = Tlv {
            flags: Flags::new_response(),
            tpe: 0x3,
            length: 4,
            value: response_data.to_vec(),
        };
        Ok(response)
    }
}

impl NetConfigurator for TimeTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Time) that does not set net configuration items.");
    }
}

impl TlvSenderHandler for TimeTlv {
    fn tlv_name(&self) -> String {
        "Time".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        TimeTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::TIMESTAMP].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
        let maybe_our_command = TimeTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let TimeTlvCommand::Time { next_tlv_command } = our_command;
        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: 0x3,
                length: 4,
                value: vec![0u8; 4],
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

impl TlvSenderHandlerConfigurator for TimeTlv {}
impl TlvReflectorHandlerConfigurator for TimeTlv {}

pub struct TimeTlvReflectorConfig {}

impl TlvHandlerGenerator for TimeTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "time".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(TimeTlv {})
    }
}
