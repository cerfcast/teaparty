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

use crate::handlers::{TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator, TlvSenderHandlerConfigurator};

use std::{
    net::{SocketAddr, UdpSocket},
    str::FromStr,
};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use serde::Serialize;
use slog::{info, warn, Logger};

use crate::{
    netconf::NetConfigurator,
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    parsers::cli_bytes_parser,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

#[derive(Serialize, Clone, Debug)]
pub struct BitPattern {
    pattern: Vec<u8>,
}

impl FromStr for BitPattern {
    type Err = clap::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = vec![0u8; 0];
        for i in 0..s.len() / 2 {
            let start = 2 * i;
            let end = start + 2;

            let value: u8 = u8::from_str_radix(&s[start..end], 16)
                .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
            result.push(value);
        }
        Ok(BitPattern { pattern: result })
    }
}

impl BitPattern {
    fn get_pattern(&self) -> Vec<u8> {
        self.pattern.clone()
    }
}

#[derive(Default, Debug)]
pub struct BitErrorRateTlv {
    padding: Vec<u8>,
    error_count: u32,
    pattern: Option<Vec<u8>>,
}
#[derive(Subcommand, Clone, Debug)]
enum BitErrorRateTlvCommand {
    BitErrorRate {
        #[arg(short, default_value_t = 64)]
        size: u16,

        #[arg(long)]
        pattern: Option<BitPattern>,

        #[arg(long)]
        padding: Option<String>,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl BitErrorRateTlv {
    fn bytes_from_pattern(pattern: &[u8], len: usize) -> Vec<u8> {
        if len == 0 || pattern.is_empty() {
            return vec![0; len];
        }
        let multiple = len / pattern.len();
        pattern.repeat(multiple)
    }
}

impl TlvReflectorHandler for BitErrorRateTlv {
    fn tlv_name(&self) -> String {
        "Bit Error Rate".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::BER_COUNT, Tlv::BER_PATTERN].to_vec()
    }

    fn request_fixup(
        &mut self,
        request: &mut StampMsg,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "BER TLV is fixing up a request (in particular, its length)"
        );

        // There is nothing for us to fixup!
        if !request.tlvs.contains(Tlv::BER_COUNT) {
            return Ok(());
        }

        // We must have padding!
        if !request.tlvs.contains(Tlv::PADDING) {
            warn!(
                logger,
                "An incoming packet that contains a BER count does not have the required padding."
            );
            return Err(StampError::MalformedTlv(Error::FieldMissing(Tlv::PADDING)));
        }

        let padding = request
            .tlvs
            .find(Tlv::PADDING)
            .ok_or(StampError::MalformedTlv(Error::FieldMissing(Tlv::PADDING)))?;

        // Record the padding value so that we can verify it later.
        self.padding.extend_from_slice(&padding.value);

        Ok(())
    }

    fn pre_send_fixup(
        &mut self,
        response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "BER TLV is fixing up a response (in particular, its BER count)"
        );

        // Try to find a valid pattern -- start with the one that might have been included in the test
        // packet using the Bit Error Pattern TLV.
        let pattern = self
            .pattern
            .clone()
            // If that doesn't exist, try to get one from the session.
            .or(_session
                .as_ref()
                .and_then(|session| session.ber.as_ref().map(|ber| ber.get_pattern())))
            // And, if that doesn't exist, then just give an empty pattern!
            .unwrap_or_default();

        // Now, whatever the length of the padding, we need to expand the pattern for comparison
        let pattern = Self::bytes_from_pattern(&pattern, self.padding.len());

        self.error_count = pattern
            .iter()
            .zip(&self.padding)
            .fold(0, |acc, (l, r)| acc + if *l != *r { 1 } else { 0 });

        info!(
            logger,
            "There were {} differences between received and expected bits.", self.error_count
        );

        if let Some(ber_tlv) = response
            .tlvs
            .iter_mut()
            .find(|tlv| tlv.tpe == Tlv::BER_COUNT)
        {
            ber_tlv
                .value
                .copy_from_slice(&u32::to_be_bytes(self.error_count));
        }

        // Now, no matter what, recreate the padding from the pattern
        // so that errors can be detected on the reverse path.
        if let Some(padding_tlv) = response.tlvs.iter_mut().find(|tlv| tlv.tpe == Tlv::PADDING) {
            padding_tlv.value[0..pattern.len()].copy_from_slice(&pattern);
        } else {
            warn!(
                logger,
                "BER TLV fixup process could not find the PADDING TLV to correct"
            );
        }

        Ok(())
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
        let mut response_tlv = tlv.clone();

        // There is only so much that can be done here ...
        // This TLV handler is registered for the family of BER TLVs.
        // That means until the entire set of TLVs in the test packet is
        // handled, there will be no way to know whether there was a Bit Error Pattern TLV
        // that specifies how to compare the values in the padding or whether
        // the comparison should be made against a pattern generated by
        // some other source.
        // So, we simply accumulate information so that the source material
        // is available when we are given the chance to fixup the response
        // before it is generated.

        match tlv.tpe {
            Tlv::BER_COUNT => {
                if !tlv.is_all_zeros() {
                    return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                        "BER Count".to_string(),
                    )));
                }
                response_tlv.flags = Flags::new_response();
                Ok(response_tlv)
            }
            Tlv::BER_PATTERN => {
                if tlv.length != 0 {
                    info!(
                        logger,
                        "Found a pattern for BER analysis in a Bit Error Pattern TLV: {:x?}",
                        tlv.value
                    );
                    self.pattern = Some(Self::bytes_from_pattern(&tlv.value, self.padding.len()));
                }

                response_tlv.flags = Flags::new_response();
                Ok(response_tlv)
            }
            _ => unreachable!(),
        }
    }
}

impl NetConfigurator for BitErrorRateTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Bit Error Rate) that does not set net configuration items.");
    }
}

impl TlvSenderHandler for BitErrorRateTlv {
    fn tlv_name(&self) -> String {
        "Bit Error Rate".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        BitErrorRateTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::BER_COUNT, Tlv::BER_PATTERN].to_vec()
    }

    fn pre_send_fixup(
        &mut self,
        response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "BER TLV is fixing up a response (in particular, its BER count)"
        );

        // Try to find a valid pattern -- start with the one that might have been included in the test
        // packet using the Bit Error Pattern TLV.
        let pattern = self
            .pattern
            .clone()
            // If that doesn't exist, try to get one from the session.
            .or(_session
                .as_ref()
                .and_then(|session| session.ber.as_ref().map(|ber| ber.get_pattern())))
            // And, if that doesn't exist, then just give an empty pattern!
            .unwrap_or_default();

        // Now, whatever the length of the padding, we need to expand the pattern for comparison
        let pattern = Self::bytes_from_pattern(&pattern, self.padding.len());

        self.error_count = pattern
            .iter()
            .zip(&self.padding)
            .fold(0, |acc, (l, r)| acc + if *l != *r { 1 } else { 0 });

        info!(
            logger,
            "There were {} differences between received and expected bits.", self.error_count
        );

        if let Some(ber_tlv) = response
            .tlvs
            .iter_mut()
            .find(|tlv| tlv.tpe == Tlv::BER_COUNT)
        {
            ber_tlv
                .value
                .copy_from_slice(&u32::to_be_bytes(self.error_count));
        }

        // Now, no matter what, recreate the padding from the pattern
        // so that errors can be detected on the reverse path.
        if let Some(padding_tlv) = response.tlvs.iter_mut().find(|tlv| tlv.tpe == Tlv::PADDING) {
            padding_tlv.value[0..pattern.len()].copy_from_slice(&pattern);
        } else {
            warn!(
                logger,
                "BER TLV fixup process could not find the PADDING TLV to correct"
            );
        }

        Ok(())
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = BitErrorRateTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let BitErrorRateTlvCommand::BitErrorRate {
            size: user_size,
            pattern: user_pattern,
            padding: user_padding,
            next_tlv_command,
        } = our_command;

        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        let actual_padding = if let Some(user_padding) = user_padding {
            cli_bytes_parser(user_padding, |_| {
                clap::Error::new(clap::error::ErrorKind::InvalidValue)
            })?
        } else if let Some(user_pattern) = user_pattern.as_ref() {
            Self::bytes_from_pattern(&user_pattern.get_pattern(), user_size as usize)
        } else {
            vec![0u8; user_size as usize]
        };

        let mut tlvs = vec![
            Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::BER_COUNT,
                length: 4,
                value: vec![0u8; 4],
            },
            Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::PADDING,
                length: actual_padding.len() as u16,
                value: actual_padding,
            },
        ];

        if let Some(user_pattern) = &user_pattern {
            let user_pattern = user_pattern.get_pattern();
            tlvs.push(Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::BER_PATTERN,
                length: user_pattern.len() as u16,
                value: user_pattern,
            });
        }

        Ok(Some((tlvs, next_tlv_command)))
    }
}

impl TlvReflectorHandlerConfigurator for BitErrorRateTlv {}
impl TlvSenderHandlerConfigurator for BitErrorRateTlv {}

pub struct BitErrorRateTlvReflectorConfig {}

impl TlvHandlerGenerator for BitErrorRateTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "reflected-control".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(BitErrorRateTlv::default())
    }
}
