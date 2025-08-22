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

use crate::handlers::{
    TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator,
    TlvSenderHandlerConfigurator,
};

use crate::netconf::NetConfigurator;

use std::net::{SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand, ValueEnum};
use slog::{info, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

pub struct AccessReportTlv {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AccessReportAccessId {
    ThreeGPP,
    NonThreeGPP,
}

impl From<AccessReportAccessId> for u8 {
    fn from(value: AccessReportAccessId) -> u8 {
        match value {
            AccessReportAccessId::ThreeGPP => 1 << 4,
            AccessReportAccessId::NonThreeGPP => 2 << 4,
        }
    }
}

impl TryFrom<u8> for AccessReportAccessId {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = value >> 4;
        if value == 1 {
            Ok(AccessReportAccessId::ThreeGPP)
        } else if value == 2 {
            Ok(AccessReportAccessId::NonThreeGPP)
        } else {
            Err(Error::FieldValueInvalid("Access ID".to_string()))
        }
    }
}

#[derive(Subcommand, Clone, Debug)]
enum AccessReportTlvCommand {
    AccessReport {
        #[arg(value_enum, default_value_t=AccessReportAccessId::NonThreeGPP)]
        access_id: AccessReportAccessId,

        /// Whether the access mode is active.
        #[arg(short)]
        active: bool,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}
impl TlvReflectorHandler for AccessReportTlv {
    fn tlv_name(&self) -> String {
        "AccessReport".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::ACCESSREPORT].to_vec()
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
        info!(logger, "I am in the AccessReport TLV handler!");

        let access_id = TryInto::<AccessReportAccessId>::try_into(tlv.value[0])
            .map_err(StampError::MalformedTlv)?;

        let active = if tlv.value[1] == 1 {
            true
        } else if tlv.value[1] == 0 {
            false
        } else {
            return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                "Active".to_string(),
            )));
        };

        info!(
            logger,
            "Received an Access Report TLV: {:?} is {}active.",
            access_id,
            if !active { "not " } else { "" }
        );

        let mut result_tlv = tlv.clone();

        result_tlv.flags.set_integrity(false);
        result_tlv.flags.set_unrecognized(false);
        Ok(result_tlv)
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

impl NetConfigurator for AccessReportTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (AccessReport) that does not set net configuration items.");
    }
}

impl TlvSenderHandler for AccessReportTlv {
    fn tlv_name(&self) -> String {
        "AccessReport".into()
    }

    fn tlv_sender_command(&self, command: Command) -> Command {
        AccessReportTlvCommand::augment_subcommands(command)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::ACCESSREPORT].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
        let maybe_our_command = AccessReportTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let AccessReportTlvCommand::AccessReport {
            access_id,
            active,
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
                tpe: Tlv::ACCESSREPORT,
                length: 4,
                value: vec![access_id.into(), active.into(), 0, 0],
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

impl TlvReflectorHandlerConfigurator for AccessReportTlv {}
impl TlvSenderHandlerConfigurator for AccessReportTlv {}

pub struct AccessReportTlvReflectorConfig {}

impl TlvHandlerGenerator for AccessReportTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "access-report".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(AccessReportTlv {})
    }
}
