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
    ntp::TimeSource,
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

pub struct FollowupTlv {}

#[derive(Subcommand, Clone, Debug)]
enum FollowupTlvCommand {
    Followup {
        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl FollowupTlv {
    const TLV_LENGTH: u16 = 16;
}
impl TlvReflectorHandler for FollowupTlv {
    fn tlv_name(&self) -> String {
        "Followup".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::FOLLOWUP].to_vec()
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
        info!(logger, "Handling the response in the Followup Tlv.");

        if tlv.length != Self::TLV_LENGTH {
            return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                "Length".to_string(),
                Self::TLV_LENGTH as usize,
                tlv.length as usize,
            )));
        }

        let mut response_body = [0u8; Self::TLV_LENGTH as usize];

        if let Some(session) = _session {
            if let Some(latest) = session.history.latest() {
                // Put the last sequence number in the first 4 bytes.
                response_body[0..4].copy_from_slice(&latest.sequence.to_be_bytes());
                // Put the time that we sent out the last packet in 8 bytes.
                response_body[4..12].copy_from_slice(&Into::<Vec<u8>>::into(latest.sent_time));
                // Until further notice, we believe that our times come from a software clock.
                response_body[12] = Into::<u8>::into(TimeSource::SWLocal);
            }
        }

        assert!(response_body.len() == 16);

        Ok(Tlv {
            flags: Flags::new_response(),
            tpe: Tlv::FOLLOWUP,
            length: Self::TLV_LENGTH,
            value: response_body.to_vec(),
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

impl TlvHandler for FollowupTlv {
    fn handle_netconfig_error(
        &mut self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Followup) that does not set net configuration items.");
    }
}
impl TlvSenderHandler for FollowupTlv {
    fn tlv_name(&self) -> String {
        "Followup".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        FollowupTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::FOLLOWUP].to_vec()
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = FollowupTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let FollowupTlvCommand::Followup { next_tlv_command } = our_command;
        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::FOLLOWUP,
                length: Self::TLV_LENGTH,
                value: vec![0u8; Self::TLV_LENGTH as usize],
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

pub struct FollowupTlvReflectorConfig {}

impl TlvHandlerGenerator for FollowupTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "followup".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandler + Send> {
        Box::new(FollowupTlv {})
    }
}
