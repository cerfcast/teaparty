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

use std::{fmt::Display, net::SocketAddr};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand, ValueEnum};
use slog::info;

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::NetConfiguration,
    netconf::NetConfigurator,
    parameters::{TestArgumentKind, TestArguments},
    server::SessionData,
    stamp::StampError,
    tlv::{self, Flags, Tlv},
};

#[derive(Default, Debug)]
pub struct ReflectedFixedHeaderDataTlv {
    pub tp: ReflectedFixedHeaderDataType,
    pub value: Vec<u8>,
}

impl TryFrom<&Tlv> for ReflectedFixedHeaderDataTlv {
    type Error = StampError;
    fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
        if value.length == 20 {
            Ok(ReflectedFixedHeaderDataTlv {
                tp: ReflectedFixedHeaderDataType::Ipv4,
                value: value.value.clone(),
            })
        } else if value.length == 60 {
            Ok(ReflectedFixedHeaderDataTlv {
                tp: ReflectedFixedHeaderDataType::Ipv6,
                value: value.value.clone(),
            })
        } else {
            Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
                "Fixed Headers Reflection Length".to_string(),
                20,
                value.length as usize,
            )))
        }
    }
}

#[derive(Default, Debug, ValueEnum, Clone)]
pub enum ReflectedFixedHeaderDataType {
    #[default]
    Ipv4,
    Ipv6,
}

impl Display for ReflectedFixedHeaderDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReflectedFixedHeaderDataType::Ipv4 => write!(f, "Ipv4"),
            ReflectedFixedHeaderDataType::Ipv6 => write!(f, "Ipv6"),
        }
    }
}

#[derive(Subcommand, Clone, Debug)]
enum ReflectedFixedHeaderDataTlvCommand {
    FixedHeadersReflection {
        #[arg(short, default_value_t = ReflectedFixedHeaderDataType::Ipv4)]
        tpe: ReflectedFixedHeaderDataType,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl TlvReflectorHandler for ReflectedFixedHeaderDataTlv {
    fn tlv_name(&self) -> String {
        "Reflected Fixed Header Data".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_FIXED_HEADER_DATA].to_vec()
    }

    fn handle(
        &mut self,
        tlv: &tlv::Tlv,
        parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        _session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        let mut response_tlv = tlv.clone();
        response_tlv.flags = Flags::new_response();

        // By default, assume that this TLV is unrecognized. When
        // data is actually put in it (pre_send_fixup), the value
        // will be changed!
        response_tlv.flags.set_unrecognized(true);

        let parameter_value =
            &parameters.get_parameter_value::<Vec<u8>>(TestArgumentKind::RawIpHdr)?[0];
        if !parameter_value.is_empty() {
            let fixed_header_tlv: ReflectedFixedHeaderDataTlv =
                TryInto::<ReflectedFixedHeaderDataTlv>::try_into(tlv)?;
            info!(
                logger,
                "There are {} bytes from an IP header for this request: {:x?}",
                parameter_value.len(),
                parameter_value
            );

            match fixed_header_tlv.tp {
                ReflectedFixedHeaderDataType::Ipv4 => {
                    if parameter_value.len() != 20 {
                        return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
                            "Reflected Fixed Header Data".to_string(),
                            20,
                            parameter_value.len(),
                        )));
                    }
                    response_tlv.flags.set_unrecognized(false);
                    response_tlv.length = parameter_value.len() as u16;
                    response_tlv.value = parameter_value.clone();
                }
                ReflectedFixedHeaderDataType::Ipv6 => {
                    if parameter_value.len() != 60 {
                        return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
                            "Reflected Fixed Header Data".to_string(),
                            60,
                            parameter_value.len(),
                        )));
                    }
                    response_tlv.flags.set_unrecognized(false);
                    response_tlv.length = parameter_value.len() as u16;
                    response_tlv.value = parameter_value.clone();
                }
            }
        }
        Ok(response_tlv)
    }
}

impl NetConfigurator for ReflectedFixedHeaderDataTlv {}

impl TlvSenderHandler for ReflectedFixedHeaderDataTlv {
    fn tlv_name(&self) -> String {
        "Reflected Fixed Header Data".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        ReflectedFixedHeaderDataTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_FIXED_HEADER_DATA].to_vec()
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = ReflectedFixedHeaderDataTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let ReflectedFixedHeaderDataTlvCommand::FixedHeadersReflection {
            tpe,
            next_tlv_command,
        } = our_command;

        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };
        let length = match tpe {
            ReflectedFixedHeaderDataType::Ipv4 => 20,
            ReflectedFixedHeaderDataType::Ipv6 => 60,
        };
        Ok(Some((
            vec![Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::REFLECTED_FIXED_HEADER_DATA,
                length,
                value: vec![0u8; length as usize],
            }],
            next_tlv_command,
        )))
    }
}

impl TlvSenderHandlerConfigurator for ReflectedFixedHeaderDataTlv {}
impl TlvReflectorHandlerConfigurator for ReflectedFixedHeaderDataTlv {}

pub struct ReflectedFixedHeaderDataTlvReflectorConfig {}

impl TlvHandlerGenerator for ReflectedFixedHeaderDataTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "fixed-header".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(ReflectedFixedHeaderDataTlv::default())
    }
}
