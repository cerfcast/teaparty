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
use slog::Logger;

use crate::{
    handlers::{
        TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator,
        TlvRequestResult, TlvSenderHandler, TlvSenderHandlerConfigurator,
    },
    netconf::{NetConfiguration, NetConfigurationItem, NetConfigurator},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

#[derive(Debug, Clone, Default)]
pub struct TimeTlv {
    pub sync_src_in: TimeStampSyncSources,
    pub method_in: TimeStampMethods,
    pub sync_src_out: TimeStampSyncSources,
    pub method_out: TimeStampMethods,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum TimeStampMethods {
    HWAssist,
    SWLocal,
    ControlPlane,
    #[default]
    Unknown,
}

impl From<u8> for TimeStampMethods {
    fn from(value: u8) -> Self {
        match value {
            1 => TimeStampMethods::HWAssist,
            2 => TimeStampMethods::SWLocal,
            3 => TimeStampMethods::ControlPlane,
            _ => TimeStampMethods::Unknown,
        }
    }
}

impl From<TimeStampMethods> for u8 {
    fn from(value: TimeStampMethods) -> Self {
        match value {
            TimeStampMethods::HWAssist => 1u8,
            TimeStampMethods::SWLocal => 2u8,
            TimeStampMethods::ControlPlane => 3u8,
            TimeStampMethods::Unknown => 255u8,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Default)]
pub enum TimeStampSyncSources {
    Ntp,
    Ptp,
    SSUBITS,
    GNSS,
    LocalFree,
    #[default]
    Unknown,
}

impl From<u8> for TimeStampSyncSources {
    fn from(value: u8) -> Self {
        match value {
            1 => TimeStampSyncSources::Ntp,
            2 => TimeStampSyncSources::Ptp,
            3 => TimeStampSyncSources::SSUBITS,
            4 => TimeStampSyncSources::GNSS,
            5 => TimeStampSyncSources::LocalFree,
            _ => TimeStampSyncSources::Unknown,
        }
    }
}

impl From<TimeStampSyncSources> for u8 {
    fn from(value: TimeStampSyncSources) -> Self {
        match value {
            TimeStampSyncSources::Ntp => 1u8,
            TimeStampSyncSources::Ptp => 2u8,
            TimeStampSyncSources::SSUBITS => 3u8,
            TimeStampSyncSources::GNSS => 4,
            TimeStampSyncSources::LocalFree => 5,
            TimeStampSyncSources::Unknown => 255u8,
        }
    }
}

impl TryFrom<&Tlv> for TimeTlv {
    type Error = StampError;
    fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
        if value.length < 4 {
            return Err(StampError::MalformedTlv(Error::NotEnoughData));
        }

        let sync_src_in = Into::<TimeStampSyncSources>::into(value.value[0]);
        let method_in = Into::<TimeStampMethods>::into(value.value[1]);
        let sync_src_out = Into::<TimeStampSyncSources>::into(value.value[2]);
        let method_out = Into::<TimeStampMethods>::into(value.value[3]);

        Ok(Self {
            sync_src_in,
            method_in,
            sync_src_out,
            method_out,
        })
    }
}

impl From<TimeTlv> for Vec<u8> {
    fn from(value: TimeTlv) -> Self {
        vec![
            value.sync_src_in.into(),
            value.method_in.into(),
            value.sync_src_out.into(),
            value.method_out.into(),
        ]
    }
}

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
        tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        _session: &mut Option<SessionData>,
        _logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        if !tlv.is_all_zeros() {
            return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                "Timestamp Information".to_string(),
            )));
        }

        let response = TimeTlv {
            sync_src_in: TimeStampSyncSources::Ntp,
            method_in: TimeStampMethods::SWLocal,
            sync_src_out: TimeStampSyncSources::Ntp,
            method_out: TimeStampMethods::SWLocal,
        };
        let response = Tlv {
            flags: Flags::new_response(),
            tpe: Tlv::TIMESTAMP,
            length: 4,
            value: response.into(),
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
                tpe: Tlv::TIMESTAMP,
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
        Box::new(TimeTlv::default())
    }
}

#[cfg(test)]
mod time_tlv_tests {
    use crate::{
        tlv::{Flags, Tlv},
        tlvs::time::{TimeStampMethods, TimeStampSyncSources, TimeTlv},
    };

    #[test]
    fn parse_time_tlv_test() {
        let raw_tlv = Tlv {
            tpe: Tlv::TIMESTAMP,
            flags: Flags::new_request(),
            length: 4,
            value: vec![1, 2, 2, 3],
        };

        let time_tlv = TryInto::<TimeTlv>::try_into(&raw_tlv)
            .expect("Should be able to parse the raw tlv into a time tlv");

        assert_eq!(time_tlv.method_in, TimeStampMethods::SWLocal);
        assert_eq!(time_tlv.method_out, TimeStampMethods::ControlPlane);
        assert_eq!(time_tlv.sync_src_in, TimeStampSyncSources::Ntp);
        assert_eq!(time_tlv.sync_src_out, TimeStampSyncSources::Ptp);
    }

    #[test]
    fn time_tlv_serialize_test() {
        let time_tlv = TimeTlv {
            sync_src_in: TimeStampSyncSources::Ntp,
            method_in: TimeStampMethods::SWLocal,
            sync_src_out: TimeStampSyncSources::Ntp,
            method_out: TimeStampMethods::SWLocal,
        };

        let time_tlv_raw = Into::<Vec<u8>>::into(time_tlv);

        assert_eq!(time_tlv_raw[0], 1);
        assert_eq!(time_tlv_raw[1], 2);
        assert_eq!(time_tlv_raw[2], 1);
        assert_eq!(time_tlv_raw[3], 2);
    }
}
