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

use crate::handlers::{ReflectorHandlers, TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator, TlvSenderHandlerConfigurator};
use std::sync::Arc;

use std::{
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    asymmetry::{Asymmetry, TaskResult},
    handlers::{HandlerError, TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfigurator, NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    parsers::parse_duration,
    responder::Responder,
    server::{Session, SessionData, Sessions},
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReflectedControlTlv {
    reflected_length: u16,
    count: u16,
    interval: u32,
}

impl ReflectedControlTlv {
    pub const MINIMUM_LENGTH: u16 = 8;
}

impl From<ReflectedControlTlv> for Vec<u8> {
    fn from(value: ReflectedControlTlv) -> Self {
        let mut bytes = vec![0u8; 8];
        bytes[0..2].copy_from_slice(&value.reflected_length.to_be_bytes());
        bytes[2..4].copy_from_slice(&value.count.to_be_bytes());
        bytes[4..8].copy_from_slice(&value.interval.to_be_bytes());

        bytes
    }
}

impl TryFrom<&Tlv> for ReflectedControlTlv {
    type Error = StampError;
    fn try_from(value: &Tlv) -> Result<ReflectedControlTlv, Self::Error> {
        if value.value.len() != Self::MINIMUM_LENGTH as usize {
            return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                "Length".to_string(),
                Self::MINIMUM_LENGTH as usize,
                value.value.len(),
            )));
        }
        let reflected_length: u16 =
            u16::from_be_bytes(value.value[0..2].try_into().map_err(|_| {
                StampError::MalformedTlv(Error::FieldValueInvalid("reflected_length".to_string()))
            })?);

        let count: u16 = u16::from_be_bytes(value.value[2..4].try_into().map_err(|_| {
            StampError::MalformedTlv(Error::FieldValueInvalid("count".to_string()))
        })?);

        let interval: u32 = u32::from_be_bytes(value.value[4..8].try_into().map_err(|_| {
            StampError::MalformedTlv(Error::FieldValueInvalid("interval".to_string()))
        })?);
        Ok(ReflectedControlTlv {
            reflected_length,
            count,
            interval,
        })
    }
}

#[derive(Subcommand, Clone, Debug)]
enum ReflectedControlTlvCommand {
    ReflectedControl {
        #[arg(long)]
        reflected_length: u16,

        #[arg(long)]
        count: u16,

        #[arg(long, value_parser=parse_duration)]
        interval: Duration,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

pub struct ReflectedControlTlvReflectorConfig {}

impl TlvHandlerGenerator for ReflectedControlTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "reflected-control".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(ReflectedControlTlv {
            reflected_length: 0,
            count: 0,
            interval: 0,
        })
    }
}

impl TlvReflectorHandler for ReflectedControlTlv {
    fn tlv_name(&self) -> String {
        "Reflected test packet control".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_CONTROL].to_vec()
    }

    fn request_fixup(
        &mut self,
        request: &mut StampMsg,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "Reflected Packet Control TLV is fixing up a request (in particular, its length)"
        );
        if !request.tlvs.contains(Tlv::REFLECTED_CONTROL) {
            return Ok(());
        }

        // Calculate the number of bytes in the length attributable to extra padding.
        let padding_length = request.tlvs.count_extra_padding_bytes();

        // Determine what the Session Sender wants the reflected packet's size to be.
        let reflected_control_tlv: ReflectedControlTlv = request
            .tlvs
            .find(Tlv::REFLECTED_CONTROL)
            .unwrap()
            .try_into()?;
        let reflected_control_tlv_requested_length = reflected_control_tlv.reflected_length;

        // Determine a "skinny" length -- the length of the test packet without padding.
        let raw_packet_msg_length = request
            .raw_length
            .ok_or(StampError::HandlerError(HandlerError::MissingRawSize))?;
        let skinny_packet_msg_length = raw_packet_msg_length - padding_length;

        // In all cases we will drop the padding TLVs.
        // Although we might add some back later!
        request.tlvs.drop_all_matching(Tlv::PADDING);
        request.raw_length = Some(skinny_packet_msg_length);

        info!(
            logger,
            "Reflected Packet Control TLV made the test packet skinnier: {}",
            skinny_packet_msg_length
        );

        // After lopping off all the extra padding TLVs, the length the Session Sender requested
        // for the reflected packet may be longer!
        if skinny_packet_msg_length < reflected_control_tlv_requested_length as usize {
            // Calculate the amount of padding that we need to add back.
            let needed_padding_length =
                reflected_control_tlv_requested_length as usize - skinny_packet_msg_length;

            // And add it back.
            request.tlvs.tlvs.push(Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::PADDING,
                length: needed_padding_length as u16,
                value: vec![0; needed_padding_length],
            });

            info!(
                logger,
                "Reflected Packet Control TLV made test packet too skinny but readjusted: {}",
                skinny_packet_msg_length
            );
            request.raw_length = Some(skinny_packet_msg_length + needed_padding_length);
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
        info!(logger, "I am in the Reflected Packet Control TLV handler!");

        let reflected_control_tlv = TryInto::<ReflectedControlTlv>::try_into(tlv)?;

        let response = Tlv {
            flags: Flags::new_response(),
            tpe: Tlv::REFLECTED_CONTROL,
            length: Self::MINIMUM_LENGTH,
            value: reflected_control_tlv.into(),
        };
        Ok(response)
    }

    fn handle_asymmetry(
        &mut self,
        response: StampMsg,
        sessions: Option<Sessions>,
        base_destination: SocketAddr,
        base_src: SocketAddr,
        responder: Arc<Responder>,
        runtime: Arc<Asymmetry<()>>,
        logger: Logger,
    ) -> Result<(), StampError> {
        let mut found_tlv: Option<Tlv> = None;
        for tlv in response.tlvs.tlvs.iter().clone() {
            if self.tlv_sender_type().contains(&tlv.tpe) {
                found_tlv = Some(tlv.clone());
            }
        }

        if let Some(tlv) = found_tlv {
            let reflected_test_control_tlv: ReflectedControlTlv = TryFrom::<&Tlv>::try_from(&tlv)?;

            // Get our ducks in a row ...
            let mut sessions = sessions.clone();
            let mut sent_packet_count = 0usize;

            // Before we get started, let's bump up the reference count on the
            // session so that it's not taken away from us.
            if let Some(sessions) = sessions.as_mut() {
                let query_session = Session::new(base_destination, base_src, response.ssid.clone());
                info!(
                    logger,
                    "Increasing reference count on session {:?}", query_session
                );
                sessions.increase_refcount(query_session);
            }

            let doer = move || {
                info!(
                    logger,
                    "I am here because of a Reflected Test Packet Control TLV."
                );

                // We need this query in several places ... let's just make it once.
                let query_session = Session::new(base_destination, base_src, response.ssid.clone());

                if sent_packet_count >= reflected_test_control_tlv.count as usize {
                    info!(
                        logger,
                        "Asymmetric execution resulting from a reflected test control tlv is done."
                    );
                    // Before we go, we should make sure that we give up our pin on the session.
                    if let Some(sessions) = sessions.as_ref() {
                        info!(
                            logger,
                            "Decreasing reference count on session {:?}", query_session
                        );
                        sessions.decrease_refcount(query_session);
                    }

                    return TaskResult {
                        next: None,
                        result: (),
                    };
                }

                let mut actual_response_msg = response.clone();

                if let Some(sessions) = sessions.as_mut() {
                    if let Some(mut session_data) = sessions.get_data(&query_session) {
                        session_data.sequence += 1;
                        actual_response_msg.sequence = session_data.sequence;
                    }
                }

                info!(
                        logger,
                        "About to send the {} asymmetric packet resulting from a Reflected Test Control TLV.", sent_packet_count
                    );
                sent_packet_count += 1;

                responder.respond(
                    actual_response_msg,
                    ReflectorHandlers::new(),
                    NetConfiguration::new(),
                    base_src,
                    base_destination,
                );

                TaskResult {
                    next: Some(
                        Instant::now()
                            + Duration::from_nanos(reflected_test_control_tlv.interval.into()),
                    ),
                    result: (),
                }
            };

            runtime.add(crate::asymmetry::Task {
                when: Instant::now()
                    + Duration::from_nanos(reflected_test_control_tlv.interval.into()),
                what: Box::new(doer),
            });
        }
        Ok(())
    }
}

impl TlvSenderHandler for ReflectedControlTlv {
    fn tlv_name(&self) -> String {
        "Reflected test packet control".into()
    }

    fn tlv_sender_command(&self, command: Command) -> Command {
        ReflectedControlTlvCommand::augment_subcommands(command)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_CONTROL].to_vec()
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = ReflectedControlTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let ReflectedControlTlvCommand::ReflectedControl {
            reflected_length: user_reflected_length,
            count: user_count,
            interval: user_interval,
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
                tpe: Tlv::REFLECTED_CONTROL,
                length: ReflectedControlTlv::MINIMUM_LENGTH,
                value: ReflectedControlTlv {
                    reflected_length: user_reflected_length,
                    count: user_count,
                    interval: user_interval.as_nanos().try_into().unwrap(),
                }
                .into(),
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

impl NetConfigurator for ReflectedControlTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Padding) that does not set net configuration items.");
    }
}

impl TlvSenderHandlerConfigurator for ReflectedControlTlv {}
impl TlvReflectorHandlerConfigurator for ReflectedControlTlv {}

#[cfg(test)]
mod reflected_control_tlv_tests {
    use crate::{tlv::Flags, tlv::Tlv, tlvs::reflectedcontrol::ReflectedControlTlv};

    #[test]
    fn simple_reflected_control_tlv_parser_roundtrip() {
        let reflected_control_tlv = ReflectedControlTlv {
            reflected_length: 50,
            count: 20,
            interval: 5,
        };
        let reflected_control_tlv_bytes = Into::<Vec<u8>>::into(reflected_control_tlv.clone());
        let raw_tlv = Tlv {
            tpe: Tlv::REFLECTED_CONTROL,
            length: reflected_control_tlv_bytes.len() as u16,
            value: reflected_control_tlv_bytes,
            flags: Flags::new_request(),
        };
        let parsed_reflected_control_tlv = TryInto::<ReflectedControlTlv>::try_into(&raw_tlv)
            .expect("Should be able to parse the roundtrip bytes.");

        assert!(reflected_control_tlv == parsed_reflected_control_tlv);
    }
}
