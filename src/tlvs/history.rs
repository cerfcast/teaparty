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
use std::sync::{Arc, Mutex};

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

pub struct HistoryTlv {}

impl HistoryTlv {
    pub const OCTETS_PER_ENTRY: usize = 32;
}

#[derive(Subcommand, Clone, Debug)]
enum HistoryTlvCommand {
    History {
        #[arg(long, default_value_t = 3)]
        length: usize,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}
impl TlvReflectorHandler for HistoryTlv {
    fn tlv_name(&self) -> String {
        "History".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::HISTORY].to_vec()
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
        info!(logger, "I am in the History TLV handler!");

        let history_entries_requested = tlv.length as usize / Self::OCTETS_PER_ENTRY;
        info!(
            logger,
            "Requesting {} history entries", history_entries_requested
        );

        let mut history_bytes = if let Some(session) = session {
            Into::<Vec<u8>>::into(session.history.clone())
        } else {
            vec![]
        };

        history_bytes.resize(tlv.length as usize, 0u8);

        Ok(Tlv {
            flags: Flags::new_response(),
            tpe: Tlv::HISTORY,
            length: history_bytes.len() as u16,
            value: history_bytes,
        })
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
impl TlvHandler for HistoryTlv {
    fn handle_netconfig_error(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (History) that does not set net configuration items.");
    }
}
impl TlvSenderHandler for HistoryTlv {
    fn tlv_name(&self) -> String {
        "History".into()
    }

    fn tlv_sender_command(&self, command: Command) -> Command {
        HistoryTlvCommand::augment_subcommands(command)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::HISTORY].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
        let maybe_our_command = HistoryTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let HistoryTlvCommand::History {
            length,
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
                tpe: Tlv::HISTORY,
                length: (length as u16) * Self::OCTETS_PER_ENTRY as u16,
                value: vec![0u8; length * Self::OCTETS_PER_ENTRY],
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

pub struct HistoryTlvReflectorConfig {}

impl TlvHandlerGenerator for HistoryTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "reflected-control".into()
    }

    fn generate(&self) -> Arc<Mutex<dyn TlvReflectorHandler + Send>> {
        Arc::new(Mutex::new(HistoryTlv {}))
    }

    fn configure(&self) {
        println!("Going to configure a reflected-control\n");
    }
}
