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

use crate::handlers;
use std::sync::{Arc, Mutex};

// Allow dead code in here because it is an API and, yes, there
// are fields that are not read ... yet.
#[allow(dead_code)]
pub mod ch {
    use std::{
        net::{IpAddr, SocketAddr, UdpSocket},
        str::FromStr,
        sync::Arc,
        time::{Duration, Instant},
    };

    use clap::{ArgMatches, Command, FromArgMatches, Subcommand, ValueEnum};
    use nix::sys::socket::{Ipv6ExtHeader, Ipv6ExtHeaderType};
    use serde::Serialize;
    use slog::{error, info, warn, Logger};

    use crate::{
        asymmetry::{Asymmetry, TaskResult},
        handlers::{HandlerError, TlvHandler, TlvRequestResult},
        ip::{DscpValue, EcnValue, MplsSegmentList, Srv6SegmentList},
        netconf::{
            NetConfiguration, NetConfigurationArgument, NetConfigurationItem,
            NetConfigurationItemKind,
        },
        ntp::TimeSource,
        parameters::{TestArgumentKind, TestArguments},
        parsers::{cli_bytes_parser, parse_duration},
        responder::Responder,
        server::{Session, SessionData, Sessions},
        stamp::{Ssid, StampError, StampMsg},
        tlv::{self, Error, Flags, Tlv, Tlvs},
    };

    pub struct TimeTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum TimeTlvCommand {
        Time {
            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for TimeTlv {
        fn tlv_name(&self) -> String {
            "Time".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            TimeTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::TIMESTAMP].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
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

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Time) that does not set net configuration items.");
        }
    }

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

    impl TlvHandler for DestinationPortTlv {
        fn tlv_name(&self) -> String {
            "Destination Port".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            DestinationPortTlvCommand::augment_subcommands(existing)
        }
        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::DESTINATION_PORT].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
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
                if self.tlv_type().contains(&tlv.tpe) {
                    let new_port: u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                    let mut ipv4 = source_address;
                    ipv4.set_port(new_port);
                    return (source_address, ipv4);
                }
            }
            (source_address, destination_address)
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Destination Port) that does not set net configuration items.");
        }
    }

    #[derive(Default, Debug)]
    pub struct ClassOfServiceTlv {
        // Value intended by Session-Sender to be used as the DSCP value of the reflected test packet.
        dscp1: DscpValue,
        // Value of the DSCP field of the IP header of the received test packet.
        dscp2: DscpValue,
        // Value intended by Session-Sender to be used as the DSCP value of the reflected test packet.
        ecn1: EcnValue,
        // Value of the ECN field of the IP header of the received test packet.
        ecn2: EcnValue,
        // Value which signals whether reliable DSCP information is carried in the reverse path.
        rpd: u8,
        // Value which signals whether reliable ECN information is carried in the reverse path.
        rpe: u8,
    }

    impl TryFrom<&Tlv> for ClassOfServiceTlv {
        type Error = StampError;
        fn try_from(tlv: &Tlv) -> Result<ClassOfServiceTlv, StampError> {
            if tlv.length != 4 {
                return Err(StampError::MalformedTlv(Error::NotEnoughData));
            }

            if tlv.value[2] & 0x0f != 0 || tlv.value[3] != 0 {
                return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                    "Reserved".to_string(),
                )));
            }

            let dscp1: DscpValue = ((tlv.value[0] & 0xfc) >> 2).try_into()?;
            let dscp2: DscpValue =
                (((tlv.value[0] & 0x3) << 4) | (tlv.value[1] >> 4)).try_into()?;
            let ecn2: EcnValue = ((tlv.value[1] & 0x0c) >> 2).into();
            let ecn1: EcnValue = ((tlv.value[2] & 0xc0) >> 6).into();
            let rpd: u8 = tlv.value[1] & 0x3;
            let rpe: u8 = (tlv.value[2] & 0x30) >> 4;

            Ok(Self {
                dscp1,
                dscp2,
                ecn1,
                ecn2,
                rpd,
                rpe,
            })
        }
    }

    impl From<ClassOfServiceTlv> for Vec<u8> {
        fn from(value: ClassOfServiceTlv) -> Self {
            // Remember: Into trait will push the 6 bits of the DSCP into the msb!
            let dscp1_b: u8 = value.dscp1.into();
            let dscp2_b: u8 = value.dscp2.into();
            let ecn1_b: u8 = value.ecn1.into();
            let ecn2_b: u8 = value.ecn2.into();

            let dscp_byte1 = dscp1_b | (dscp2_b >> 6);
            let dscp_byte2 = (dscp2_b << 2) | (ecn2_b << 2) | value.rpd & 0x3;
            let reserved_byte1 = (ecn1_b << 6) | (value.rpe << 4);

            vec![dscp_byte1, dscp_byte2, reserved_byte1, 0]
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum ClassOfServiceTlvCommand {
        ClassOfService {
            #[arg(long, default_value = "cs1")]
            dscp: DscpValue,

            #[arg(long, default_value = "not-ect")]
            ecn: EcnValue,

            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for ClassOfServiceTlv {
        fn tlv_name(&self) -> String {
            "Class of Service".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            ClassOfServiceTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::COS].to_vec()
        }

        fn request(
            &mut self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = ClassOfServiceTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let ClassOfServiceTlvCommand::ClassOfService {
                dscp: user_dscp,
                ecn: user_ecn,
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
                    tpe: Tlv::COS,
                    length: 4,
                    value: vec![
                        Into::<u8>::into(user_dscp),
                        0,
                        Into::<u8>::into(user_ecn) << 6,
                        0,
                    ],
                }]
                .to_vec(),
                next_tlv_command,
            )))
        }

        fn handle(
            &mut self,
            tlv: &tlv::Tlv,
            parameters: &TestArguments,
            netconfig: &mut NetConfiguration,
            _client: SocketAddr,
            _session: &mut Option<SessionData>,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am in the Class of Service TLV handler!");

            let mut cos_tlv: ClassOfServiceTlv = TryFrom::try_from(tlv)?;

            if cos_tlv.rpd != 0 {
                return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                    "RPD".to_string(),
                )));
            }

            if cos_tlv.rpe != 0 {
                return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                    "RPE".to_string(),
                )));
            }

            let ecn_argument: u8 = match parameters.get_parameter_value::<u8>(TestArgumentKind::Ecn)
            {
                Ok(ecn_arguments) => ecn_arguments[0],
                Err(e) => return Err(e),
            };

            // Remember: DSCP bits are in the msb!
            let dscp_argument: u8 =
                match parameters.get_parameter_value::<u8>(TestArgumentKind::Dscp) {
                    Ok(dscp_arguments) => dscp_arguments[0],
                    Err(e) => return Err(e),
                };

            info!(logger, "Got ecn argument: {:x}", ecn_argument);
            info!(logger, "Got dscp argument: {:x}", dscp_argument);

            cos_tlv.ecn2 = ecn_argument.into();
            // Into from DscpValue to u8 assumes that the DSCP bits are in lsb.
            cos_tlv.dscp2 = (dscp_argument >> 2).try_into()?;

            info!(logger, "Dscp requested back? {:?}", cos_tlv.dscp1);

            netconfig.add_configuration(
                NetConfigurationItemKind::Dscp,
                NetConfigurationArgument::Dscp(cos_tlv.dscp1),
                Tlv::COS,
            );

            netconfig.add_configuration(
                NetConfigurationItemKind::Ecn,
                NetConfigurationArgument::Ecn(cos_tlv.ecn1),
                Tlv::COS,
            );

            // Must set the RPE value to 1 in reflected packet:
            cos_tlv.rpe = 1;

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: Tlv::COS,
                length: 4,
                value: cos_tlv.into(),
            };

            Ok(response)
        }
        fn handle_netconfig_error(
            &mut self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            item: NetConfigurationItem,
            logger: Logger,
        ) {
            for tlv in &mut response.tlvs.tlvs {
                if self.tlv_type().contains(&tlv.tpe) {
                    // Adjust our response to indicate that there was an error
                    // setting the reverse path parameters on the packet!
                    match item {
                        // An error setting the DSCP value means that we change the RPD!
                        NetConfigurationItem::Dscp(_) => {
                            error!(logger, "There was an error doing DSCP net configuration on reflected packet. Updating RPD value. (Class of Service Handler)");
                            tlv.value[1] |= 0x1;
                        }
                        NetConfigurationItem::Ecn(_) => {
                            error!(logger, "There was an error doing ECN net configuration on reflected packet. No semantics defined to update RPE. (Class of Service Handler)");
                        }
                        _ => {}
                    };
                }
            }
        }
    }

    pub struct LocationTlv {}

    impl LocationTlv {
        pub const DESTINATION_IP_LENGTH: u16 = 16;
        pub const DESTINATION_IP_TYPE: u8 = 5;
        pub const IPV4_DESTINATION_IP_TYPE: u8 = 6;
        pub const _IPV6_DESTINATION_IP_TYPE: u8 = 7;

        pub const SOURCE_IP_LENGTH: u16 = 16;
        pub const SOURCE_IP_TYPE: u8 = 7;
        pub const IPV4_SOURCE_IP_TYPE: u8 = 8;
        pub const _IPV6_SOURCE_IP_TYPE: u8 = 9;

        pub const SOURCE_MAC_LENGTH: u16 = 8;
        pub const SOURCE_MAC_TYPE: u8 = 1;
        pub const SOURCE_EUI48_TYPE: u8 = 2;
    }

    #[derive(Subcommand, Clone, Debug)]
    enum LocationTlvCommand {
        Location {
            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for LocationTlv {
        fn tlv_name(&self) -> String {
            "Location".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            LocationTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::LOCATION].to_vec()
        }

        fn request(
            &mut self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = LocationTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let LocationTlvCommand::Location { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            let mut sub_tlvs = Tlvs {
                tlvs: Default::default(),
                malformed: None,
            };
            sub_tlvs.tlvs.extend(vec![
                Tlv {
                    flags: Flags::new_request(),
                    tpe: Self::SOURCE_IP_TYPE,
                    length: Self::SOURCE_IP_LENGTH,
                    value: vec![0u8; Self::SOURCE_IP_LENGTH as usize],
                },
                Tlv {
                    flags: Flags::new_request(),
                    tpe: Self::SOURCE_MAC_TYPE,
                    length: Self::SOURCE_MAC_LENGTH,
                    value: vec![0; Self::SOURCE_MAC_LENGTH as usize],
                },
            ]);

            let mut request_value = vec![0u8, 0, 0, 0];
            let sub_tlv_value: Vec<u8> = sub_tlvs.into();
            request_value.extend_from_slice(&sub_tlv_value);

            Ok(Some((
                [Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::LOCATION,
                    length: request_value.len() as u16,
                    value: request_value,
                }]
                .to_vec(),
                next_tlv_command,
            )))
        }

        fn handle(
            &mut self,
            tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _netconfig: &mut NetConfiguration,
            client: SocketAddr,
            _session: &mut Option<SessionData>,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            let dst_port_bytes = &tlv.value[0..2];
            let src_port_bytes = &tlv.value[2..4];

            let dst_port = u16::from_be_bytes(dst_port_bytes.try_into().unwrap());
            let src_port = u16::from_be_bytes(src_port_bytes.try_into().unwrap());

            if dst_port != 0 {
                return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                    "Destination port".to_string(),
                )));
            }

            if src_port != 0 {
                return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                    "Source port".to_string(),
                )));
            }

            let start_offset = 4usize;
            let mut sub_tlvs: Tlvs = TryFrom::<&[u8]>::try_from(&tlv.value[start_offset..])?;

            for sub_tlv in sub_tlvs.tlvs.iter_mut() {
                if !sub_tlv.is_all_zeros() {
                    return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                        format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                    )));
                }

                match sub_tlv.tpe {
                    Self::SOURCE_IP_TYPE => {
                        if sub_tlv.length != Self::SOURCE_IP_LENGTH {
                            return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                                format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                                Self::SOURCE_IP_LENGTH as usize,
                                sub_tlv.length as usize,
                            )));
                        }
                        sub_tlv.flags.set_unrecognized(false);
                        sub_tlv.flags.set_malformed(false);
                        sub_tlv.flags.set_integrity(true);

                        sub_tlv.tpe = Self::IPV4_SOURCE_IP_TYPE;

                        match client.ip() {
                            IpAddr::V4(v4) => {
                                info!(logger, "The location TLV is requesting a source IP address; responding with {}", v4);
                                sub_tlv.value[0..4].copy_from_slice(&v4.octets());
                            }
                            IpAddr::V6(_) => {
                                panic!("Ipv6 is not yet supported");
                            }
                        }
                    }
                    // Note: We do not do anything here except validate. We need to do the server's outgoing information
                    // in order to complete this TLV, so we do that in the prepare_response_socket.
                    Self::DESTINATION_IP_TYPE => {
                        if sub_tlv.length != Self::DESTINATION_IP_LENGTH {
                            return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                                format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                                Self::DESTINATION_IP_LENGTH as usize,
                                sub_tlv.length as usize,
                            )));
                        }
                        sub_tlv.flags.set_unrecognized(false);
                        sub_tlv.flags.set_malformed(false);
                        sub_tlv.flags.set_integrity(true);

                        sub_tlv.tpe = Self::IPV4_DESTINATION_IP_TYPE;

                        match client.ip() {
                            IpAddr::V4(_) => {
                                // See above.
                                info!(logger, "The location TLV is requesting a destination IP address; further processing to happen later.");
                            }
                            IpAddr::V6(_) => {
                                panic!("Ipv6 is not yet supported");
                            }
                        }
                    }
                    Self::SOURCE_MAC_TYPE => {
                        if sub_tlv.length != Self::SOURCE_MAC_LENGTH {
                            return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                                format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                                Self::DESTINATION_IP_LENGTH as usize,
                                sub_tlv.length as usize,
                            )));
                        }
                        sub_tlv.flags.set_unrecognized(false);
                        sub_tlv.flags.set_malformed(false);
                        sub_tlv.flags.set_integrity(true);

                        sub_tlv.tpe = Self::SOURCE_EUI48_TYPE;

                        let peer_mac_address = &_parameters
                            .get_parameter_value::<Vec<u8>>(TestArgumentKind::PeerMacAddress)
                            .unwrap()[0];
                        info!(logger, "The location TLV is requesting a source mac address; responding with {:?}", peer_mac_address);

                        sub_tlv.value = peer_mac_address.clone();
                        sub_tlv.value.extend_from_slice(&[0u8; 2]);
                    }

                    x => {
                        warn!(logger, "Unhandled location sub TLV with type {}", x);
                    }
                }
            }

            let mut result_value = vec![0u8; 4];
            for sub_tlv in sub_tlvs.tlvs.iter() {
                result_value.extend_from_slice(&Into::<Vec<u8>>::into(sub_tlv));
            }

            if let Some(malformed) = sub_tlvs.malformed {
                result_value.extend_from_slice(&malformed.bytes);
            }

            assert!(result_value.len() == tlv.value.len());

            Ok(Tlv {
                flags: Flags::new_response(),
                tpe: Tlv::LOCATION,
                length: result_value.len() as u16,
                value: result_value,
            })
        }
        fn pre_send_fixup(
            &mut self,
            response: &mut StampMsg,
            socket: &UdpSocket,
            _config: &mut NetConfiguration,
            _session: &Option<SessionData>,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Preparing the response socket in the Location Tlv.");

            for tlv in response.tlvs.tlvs.iter_mut() {
                if self.tlv_type().contains(&tlv.tpe) {
                    let start_offset = 4usize;
                    let mut sub_tlvs: Tlvs =
                        TryFrom::<&[u8]>::try_from(&tlv.value[start_offset..])?;

                    for sub_tlv in sub_tlvs.tlvs.iter_mut() {
                        // We can skip all error checking! We know that we have been sanitized.
                        match sub_tlv.tpe {
                            Self::DESTINATION_IP_TYPE => match socket.local_addr().unwrap() {
                                SocketAddr::V4(v4) => {
                                    sub_tlv.value.copy_from_slice(&v4.ip().octets());
                                }
                                SocketAddr::V6(_) => {
                                    panic!("Ipv6 is not yet supported");
                                }
                            },
                            _ => {
                                // No other fields need fixup!
                            }
                        }
                    }

                    let mut result_value = vec![0u8; 4];
                    for sub_tlv in sub_tlvs.tlvs.iter() {
                        result_value.extend_from_slice(&Into::<Vec<u8>>::into(sub_tlv));
                    }
                    tlv.value.copy_from_slice(&result_value);
                    break;
                }
            }

            Ok(())
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Location) that does not set net configuration items.");
        }
    }

    pub struct UnrecognizedTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum UnrecognizedTlvCommand {
        Unrecognized {
            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for UnrecognizedTlv {
        fn tlv_name(&self) -> String {
            "Unrecognized".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            UnrecognizedTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [0].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = UnrecognizedTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let UnrecognizedTlvCommand::Unrecognized { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Ok(Some(([Tlv::unrecognized(32)].to_vec(), next_tlv_command)))
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
            info!(logger, "I am in the Unrecognized TLV handler!");
            Ok(tlv.clone())
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
        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Unrecognized) that does not set net configuration items.");
        }
    }

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

    impl TlvHandler for PaddingTlv {
        fn tlv_name(&self) -> String {
            "Padding".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            PaddingTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
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
                    length: 4 + size,
                    value: vec![0u8; 4 + size as usize],
                }]
                .to_vec(),
                next_tlv_command,
            )))
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

    impl TlvHandler for AccessReportTlv {
        fn tlv_name(&self) -> String {
            "AccessReport".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            AccessReportTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::ACCESSREPORT].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
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
        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (AccessReport) that does not set net configuration items.");
        }
    }

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

    impl TlvHandler for HistoryTlv {
        fn tlv_name(&self) -> String {
            "History".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            HistoryTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::HISTORY].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
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

    impl TlvHandler for FollowupTlv {
        fn tlv_name(&self) -> String {
            "Followup".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            FollowupTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
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
                    StampError::MalformedTlv(Error::FieldValueInvalid(
                        "reflected_length".to_string(),
                    ))
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

    impl TlvHandler for ReflectedControlTlv {
        fn tlv_name(&self) -> String {
            "Reflected test packet control".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            ReflectedControlTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> Vec<u8> {
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

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Reflected Test Packet Control TLV) that does not set net configuration items.");
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
                if self.tlv_type().contains(&tlv.tpe) {
                    found_tlv = Some(tlv.clone());
                }
            }

            if let Some(tlv) = found_tlv {
                let reflected_test_control_tlv: ReflectedControlTlv =
                    TryFrom::<&Tlv>::try_from(&tlv)?;

                // Get our ducks in a row ...
                let mut sessions = sessions.clone();
                let mut sent_packet_count = 0usize;

                // Before we get started, let's bump up the reference count on the
                // session so that it's not taken away from us.
                if let Some(sessions) = sessions.as_mut() {
                    let query_session =
                        Session::new(base_destination, base_src, response.ssid.clone());
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
                    let query_session =
                        Session::new(base_destination, base_src, response.ssid.clone());

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
                        None,
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

    #[derive(Debug, Default)]
    pub struct HmacTlv {
        hmac: [u8; HmacTlv::LENGTH as usize],
    }

    impl HmacTlv {
        pub const LENGTH: u16 = 16;
    }

    impl From<HmacTlv> for Vec<u8> {
        fn from(value: HmacTlv) -> Self {
            let mut bytes = vec![0u8; HmacTlv::LENGTH as usize];
            bytes[0..HmacTlv::LENGTH as usize].copy_from_slice(&value.hmac);

            bytes
        }
    }

    impl TryFrom<&Tlv> for HmacTlv {
        type Error = StampError;
        fn try_from(value: &Tlv) -> Result<HmacTlv, Self::Error> {
            if value.tpe != Tlv::HMAC_TLV {
                return Err(StampError::MalformedTlv(Error::WrongType(
                    Tlv::HMAC_TLV,
                    value.tpe,
                )));
            }

            if value.value.len() != Self::LENGTH as usize {
                return Err(StampError::MalformedTlv(Error::FieldWrongSized(
                    "Length".to_string(),
                    Self::LENGTH as usize,
                    value.value.len(),
                )));
            }

            let mut hmac_result = HmacTlv { hmac: [0; 16] };
            hmac_result.hmac.copy_from_slice(&value.value);
            Ok(hmac_result)
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum HmacTlvCommand {
        Hmac { next_tlv_command: Vec<String> },
    }

    impl TlvHandler for HmacTlv {
        fn tlv_name(&self) -> String {
            "HMAC TLV".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            HmacTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::HMAC_TLV].to_vec()
        }

        fn request_fixup(
            &mut self,
            request: &mut StampMsg,
            _session: &Option<SessionData>,
            logger: Logger,
        ) -> Result<(), StampError> {
            // By now we know that there is nothing malformed. We can safely call find
            // without worrying about getting two results.
            if !request.tlvs.contains(Tlv::HMAC_TLV) {
                return Ok(());
            }

            if let Some(SessionData { key: Some(key), .. }) = _session {
                let hmac = request.tlvs.calculate_hmac(request.sequence, key)?;
                if let Some(hmac_tlv) = request.tlvs.find(Tlv::HMAC_TLV) {
                    if hmac_tlv.value == hmac {
                        return Ok(());
                    }
                    info!(logger, "Verification of the TLV HMAC on a received STAMP packet failed; expected {:x?} vs received {:x?}", hmac_tlv.value, hmac);
                    return Err(StampError::InvalidSignature);
                }
            }
            info!(
                logger,
                "Verification of the TLV HMAC failed because of missing session."
            );
            Err(StampError::InvalidSignature)
        }

        fn request(
            &mut self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = HmacTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let HmacTlvCommand::Hmac { next_tlv_command } = our_command;

            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Ok(Some((
                [Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::HMAC_TLV,
                    length: HmacTlv::LENGTH,
                    value: HmacTlv { hmac: [0; 16] }.into(),
                }]
                .to_vec(),
                next_tlv_command,
            )))
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
            info!(logger, "Handling an HMAC TLV!");

            let hmac_tlv = TryInto::<HmacTlv>::try_into(tlv)?;

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: Tlv::HMAC_TLV,
                length: Self::LENGTH,
                value: hmac_tlv.into(),
            };
            Ok(response)
        }
        fn pre_send_fixup(
            &mut self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            _config: &mut NetConfiguration,
            session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            if let Some(SessionData {
                sequence: _,
                reference_count: _,
                last: _,
                key: Some(key),
                ber: _,
                ssid: _,
                history: _,
            }) = session
            {
                response.tlvs.stamp_hmac(response.sequence, key)?;
            }
            Ok(())
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (HMAC TLV) that does not set net configuration items.");
        }
    }

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

    impl TlvHandler for BitErrorRateTlv {
        fn tlv_name(&self) -> String {
            "Bit Error Rate".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            BitErrorRateTlvCommand::augment_subcommands(existing)
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
            if let Some(padding_tlv) = response.tlvs.iter_mut().find(|tlv| tlv.tpe == Tlv::PADDING)
            {
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
                        self.pattern =
                            Some(Self::bytes_from_pattern(&tlv.value, self.padding.len()));
                    }

                    response_tlv.flags = Flags::new_response();
                    Ok(response_tlv)
                }
                _ => unreachable!(),
            }
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Bit Error Rate) that does not set net configuration items.");
        }
    }

    #[derive(Default, Debug)]
    pub struct V6ExtensionHeadersReflectionTlv {
        headers: Vec<Ipv6ExtHeader>,
    }

    #[derive(Subcommand, Clone, Debug)]
    enum V6ExtensionHeadersTlvCommand {
        V6ExtensionHeaderReflection {
            #[arg(short, default_value_t = 8)]
            size: u16,

            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for V6ExtensionHeadersReflectionTlv {
        fn tlv_name(&self) -> String {
            "IPv6 Extension Header Reflection".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            V6ExtensionHeadersTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::V6_EXTENSION_HEADERS_REFLECTION].to_vec()
        }

        fn request(
            &mut self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = V6ExtensionHeadersTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let V6ExtensionHeadersTlvCommand::V6ExtensionHeaderReflection {
                size,
                next_tlv_command,
            } = our_command;

            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Ok(Some((
                vec![Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::V6_EXTENSION_HEADERS_REFLECTION,
                    length: size,
                    value: vec![0u8; size as usize],
                }],
                next_tlv_command,
            )))
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

            self.headers = parameters.get_parameter_value(TestArgumentKind::HeaderOption)?;
            if !self.headers.is_empty() {
                info!(
                    logger,
                    "There are {} IPv6 headers for this request: {:x?}",
                    self.headers.len(),
                    self.headers
                );
            }

            Ok(response_tlv)
        }

        fn pre_send_fixup(
            &mut self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            _config: &mut NetConfiguration,
            _session: &Option<SessionData>,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "IPv6 Header Option TLV is fixing up a response");

            let header_options = response
                .tlvs
                .iter_mut()
                .filter(|tlv| tlv.tpe == Tlv::V6_EXTENSION_HEADERS_REFLECTION);

            for (ipv6_header, tlv) in self.headers.iter().as_slice().iter().zip(header_options) {
                // Punt if the IPv6 header is not at least 4 bytes!
                if ipv6_header.header_body.len() < 4 {
                    info!(logger, "Skipping IPv6 Header that is shorter than 4 bytes.");
                    continue;
                }
                if ipv6_header.header_body.len() + 2 != (tlv.length as usize) {
                    info!(
                        logger,
                        "IPv6 extension header size does not match TLV length."
                    );
                    continue;
                }
                if !tlv.is_all_zeros() {
                    if tlv.length < 4 {
                        info!(
                            logger,
                            "Header Option TLV match contains a guard but is shorter than 4 bytes."
                        );
                        continue;
                    }
                    if ipv6_header.header_body[0..4] != tlv.value[0..4] {
                        info!(logger, "Header Option TLV match guard is false.");
                        continue;
                    }
                }
                // All good! Copy the data!
                let mut header_raw = vec![
                    if ipv6_header.header_type == Ipv6ExtHeaderType::HopByHop {
                        0xff
                    } else {
                        0xfe
                    },
                    (((ipv6_header.header_body.len() + 2) / 8) - 1) as u8,
                ];
                ipv6_header
                    .header_body
                    .iter()
                    .for_each(|f| header_raw.push(*f));
                tlv.value.copy_from_slice(&header_raw);
                tlv.flags.set_unrecognized(false);

                _config.add_configuration(
                    NetConfigurationItemKind::ExtensionHeader,
                    NetConfigurationArgument::ExtensionHeader(ipv6_header.clone()),
                    Tlv::V6_EXTENSION_HEADERS_REFLECTION,
                );
            }

            Ok(())
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (IPv6 Header Options) that does not set net configuration items.");
        }
    }

    #[derive(Default, Debug)]
    pub struct DestinationAddressTlv {
        pub address: Option<IpAddr>,
    }

    impl TryFrom<&Tlv> for DestinationAddressTlv {
        type Error = StampError;
        fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
            if !(value.length == 4 || value.length == 16) {
                return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                    "Length must be either 4 or 16".to_string(),
                )));
            }
            let address = if value.length == 4 {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&value.value.as_slice()[0..4]);
                Into::<IpAddr>::into(bytes)
            } else {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&value.value.as_slice()[0..16]);
                Into::<IpAddr>::into(bytes)
            };
            Ok(Self {
                address: Some(address),
            })
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum DestinationAddressTlvCommand {
        DestinationAddress {
            #[arg(long)]
            address: IpAddr,

            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for DestinationAddressTlv {
        fn tlv_name(&self) -> String {
            "Destination Address".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            DestinationAddressTlvCommand::augment_subcommands(existing)
        }
        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::DESTINATION_ADDRESS].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = DestinationAddressTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let DestinationAddressTlvCommand::DestinationAddress {
                address,
                next_tlv_command,
            } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            let value = match address {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };

            Ok(Some((
                [Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::DESTINATION_ADDRESS,
                    length: value.len() as u16,
                    value,
                }]
                .to_vec(),
                next_tlv_command,
            )))
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
            info!(logger, "I am handling a destination address Tlv.");

            let has_ssid = session
                .as_ref()
                .map(|session| match session.ssid.clone() {
                    Ssid::Mbz(_) => false,
                    Ssid::Ssid(v) => v != 0,
                })
                .unwrap_or(false);

            // When there is a destination address TLV there must be an SSID.
            if !has_ssid {
                return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                    "Ssid".to_string(),
                )));
            }

            let destination_tlv = TryInto::<DestinationAddressTlv>::try_into(tlv)?;

            // Make sure that the destination address is of the same address family.
            self.address = destination_tlv.address.filter(|addr| {
                if _client.is_ipv4() && addr.is_ipv4() {
                    true
                } else if _client.is_ipv6() && addr.is_ipv6() {
                    // Yes, redundant; write for clarity.
                    true
                } else {
                    false
                }
            });

            let mut result_tlv = tlv.clone();

            // If there is no destination address, then the response should be unrecognized.
            result_tlv.flags.set_unrecognized(self.address.is_none());

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
                "Preparing the response source in the destination address Tlv by changing the source address."
            );

            if self.address.is_none() {
                return (source_address, destination_address);
            }
            let new_source_address = self.address.unwrap();

            for tlv in response.tlvs.tlvs.iter() {
                if self.tlv_type().contains(&tlv.tpe) {
                    let port = source_address.port();
                    return (
                        SocketAddr::new(new_source_address, port),
                        destination_address,
                    );
                }
            }
            (source_address, destination_address)
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Destination Address) that does not set net configuration items.");
        }
    }

    #[derive(Default, Debug)]
    pub struct ReturnPathTlv {
        pub address: Option<IpAddr>,
        pub ip_segment_list: Option<Srv6SegmentList>,
        pub mpls_segment_list: Option<MplsSegmentList>,
        pub control_code: Option<u32>,
        pub flags: Flags,
    }

    impl ReturnPathTlv {
        pub const CONTROL_CODE: u8 = 1;
        pub const RETURN_ADDRESS: u8 = 2;
        pub const MPLS_SEGMENT_LIST: u8 = 3;
        pub const SRV6_SEGMENT_LIST: u8 = 4;
    }

    impl TryFrom<&Tlv> for ReturnPathTlv {
        type Error = StampError;
        fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
            let sub_tlvs = TryInto::<Tlvs>::try_into(value.value.as_slice())?;

            let mut result = ReturnPathTlv::default();

            for tlv in &sub_tlvs.tlvs {
                match tlv.tpe {
                    ReturnPathTlv::RETURN_ADDRESS => {
                        if result.address.is_some() {
                            // It is an error to have the address specified twice.
                            return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                                "Cannot specify a Return-Address Sub TLV more than once"
                                    .to_string(),
                            )));
                        }
                        if !(tlv.length == 4 || tlv.length == 16) {
                            return Err(StampError::MalformedTlv(Error::FieldValueInvalid(
                                "Length must be either 4 or 16".to_string(),
                            )));
                        }
                        result.address = if tlv.length == 4 {
                            let mut bytes = [0u8; 4];
                            bytes.copy_from_slice(&tlv.value.as_slice()[0..4]);
                            Some(Into::<IpAddr>::into(bytes))
                        } else {
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(&tlv.value.as_slice()[0..16]);
                            Some(Into::<IpAddr>::into(bytes))
                        };
                    }
                    _ => {
                        todo!()
                    }
                }
            }

            Ok(result)
        }
    }

    impl TryFrom<&ReturnPathTlv> for Tlv {
        type Error = StampError;

        fn try_from(value: &ReturnPathTlv) -> Result<Self, Self::Error> {
            let mut sub_tlvs = Tlvs::new();
            match value.address {
                Some(IpAddr::V4(v4)) => {
                    sub_tlvs
                        .add_tlv(Tlv {
                            tpe: ReturnPathTlv::RETURN_ADDRESS,
                            flags: value.flags.clone(),
                            length: 4,
                            value: v4.octets().to_vec(),
                        })
                        .map_err(StampError::MalformedTlv)?;
                }
                Some(IpAddr::V6(v6)) => {
                    sub_tlvs
                        .add_tlv(Tlv {
                            tpe: ReturnPathTlv::RETURN_ADDRESS,
                            flags: value.flags.clone(),
                            length: 16,
                            value: v6.octets().to_vec(),
                        })
                        .map_err(StampError::MalformedTlv)?;
                }
                None => (),
            }

            let sub_tlv_bytes = Into::<Vec<u8>>::into(sub_tlvs);
            Ok(Tlv {
                tpe: Tlv::RETURN_PATH,
                flags: Flags::new_request(),
                length: sub_tlv_bytes.len() as u16,
                value: sub_tlv_bytes,
            })
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum ReturnPathTlvCommand {
        ReturnPath {
            #[arg(long)]
            address: IpAddr,

            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for ReturnPathTlv {
        fn tlv_name(&self) -> String {
            "Return Path".into()
        }

        fn tlv_cli_command(&self, existing: Command) -> Command {
            ReturnPathTlvCommand::augment_subcommands(existing)
        }
        fn tlv_type(&self) -> Vec<u8> {
            [Tlv::RETURN_PATH].to_vec()
        }

        fn request(
            &mut self,
            _: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = ReturnPathTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return Ok(None);
            }
            let our_command = maybe_our_command.unwrap();
            let ReturnPathTlvCommand::ReturnPath {
                address,
                next_tlv_command,
            } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            // Take the user's specified IP address and use it as the address in the Return-Address Sub Tlv
            let return_path_tlv = ReturnPathTlv {
                address: Some(address),
                flags: Flags::new_request(),
                ..Default::default()
            };

            Ok(Some((
                [TryInto::<Tlv>::try_into(&return_path_tlv)
                    .map_err(|_| clap::Error::new(clap::error::ErrorKind::InvalidValue))?]
                .to_vec(),
                next_tlv_command,
            )))
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
            info!(logger, "I am handling a return path Tlv.");

            // Start by creating a sub TLV.
            let mut return_path_tlv = TryInto::<ReturnPathTlv>::try_into(tlv)?;
            return_path_tlv.flags = Flags::new_response();

            self.address = return_path_tlv.address;
            return_path_tlv
                .flags
                .set_unrecognized(self.address.is_none());

            // There is an Into implementation that will convert that into a true TLV.
            let mut result_tlv = TryInto::<Tlv>::try_into(&return_path_tlv)?;
            result_tlv.flags.set_unrecognized(self.address.is_none());

            // And that is what will be reflected.
            Ok(result_tlv)
        }

        fn prepare_response_addrs(
            &mut self,
            _response: &mut StampMsg,
            source_address: SocketAddr,
            destination_address: SocketAddr,
            logger: Logger,
        ) -> (SocketAddr, SocketAddr) {
            info!(
                logger,
                "Preparing the response source in the return path address Tlv by changing the destination address."
            );
            if let Some(new_destination_address) = self.address {
                (
                    source_address,
                    (new_destination_address, destination_address.port()).into(),
                )
            } else {
                (source_address, destination_address)
            }
        }

        fn handle_netconfig_error(
            &mut self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Destination Address) that does not set net configuration items.");
        }
    }

    #[cfg(test)]
    mod custom_handlers_test {
        use crate::{
            custom_handlers::ch::ReturnPathTlv,
            stamp::StampError,
            tlv::{self, Flags, Tlv},
        };

        use super::HmacTlv;

        #[test]
        fn simple_hmac_tlv_parser_roundtrip() {
            let hmac_bytes = vec![0xeu8; HmacTlv::LENGTH as usize];
            let hmac_tlv = HmacTlv {
                hmac: hmac_bytes.clone().try_into().unwrap(),
            };
            let hmac_tlv_serialized = Into::<Vec<u8>>::into(hmac_tlv);

            assert!(hmac_tlv_serialized == hmac_bytes);
        }

        #[test]
        fn simple_hmac_tlv_parser_too_big() {
            let raw_tlv = tlv::Tlv {
                length: HmacTlv::LENGTH + 5,
                value: vec![0xeu8; HmacTlv::LENGTH as usize + 5],
                flags: Flags::new_request(),
                tpe: Tlv::HMAC_TLV,
            };
            let hmac_tlv = TryInto::<HmacTlv>::try_into(&raw_tlv);

            assert!(hmac_tlv.is_err());
            assert!(matches!(
                hmac_tlv,
                Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(..)))
            ));
        }

        #[test]
        fn simple_hmac_tlv_parser_wrong_type() {
            let raw_tlv = tlv::Tlv {
                length: HmacTlv::LENGTH + 5,
                value: vec![0xeu8; HmacTlv::LENGTH as usize + 5],
                flags: Flags::new_request(),
                tpe: Tlv::HEARTBEAT,
            };
            let hmac_tlv = TryInto::<HmacTlv>::try_into(&raw_tlv);

            assert!(hmac_tlv.is_err());
            assert!(matches!(
                hmac_tlv,
                Err(StampError::MalformedTlv(tlv::Error::WrongType(
                    Tlv::HMAC_TLV,
                    Tlv::HEARTBEAT
                )))
            ));
        }

        use super::ReflectedControlTlv;

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
        use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

        use crate::{
            handlers::TlvHandler,
            netconf::NetConfiguration,
            parameters::{TestArgument, TestArguments},
            server::SessionData,
        };

        use crate::test::stamp_handler_test_support::create_test_logger;

        use super::ClassOfServiceTlv;

        #[test]
        fn simple_cos_handler_extract_pack_test() {
            let mut args: TestArguments = Default::default();

            // AF23 is 0x16 (see below)
            args.add_argument(
                crate::parameters::TestArgumentKind::Dscp,
                TestArgument::Dscp(crate::ip::DscpValue::AF23),
            );
            args.add_argument(
                crate::parameters::TestArgumentKind::Ecn,
                TestArgument::Ecn(crate::ip::EcnValue::NotEct), // Use NotEct to keep things "simple"
            );

            let test_request_tlv = Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::COS,
                length: 4,
                value: vec![crate::ip::DscpValue::AF13.into(), 0, 0, 0],
            };

            let mut cos_handler: ClassOfServiceTlv = Default::default();

            let test_logger = create_test_logger();
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5001);

            let mut netconfig = NetConfiguration::new();

            let mut test_session_data: Option<SessionData> = None;

            let result = cos_handler
                .handle(
                    &test_request_tlv,
                    &args,
                    &mut netconfig,
                    address.into(),
                    &mut test_session_data,
                    test_logger,
                )
                .expect("COS handler should have worked");

            let expected_result = [
                Into::<u8>::into(crate::ip::DscpValue::AF13) | (0x16 >> 4), // Shift 0x16 (see above) right by 4 to isolate top 2 bits.
                (0x16 << 4), // Shift 0x16 (see above) left to put the bottom 4 bits in the top 4 bits of a u8.
                0x10,
                0,
            ];

            assert!(result
                .value
                .iter()
                .zip(expected_result.iter())
                .all(|(l, r)| l == r));
        }

        use crate::{custom_handlers::ch::LocationTlv, netconf};

        #[test]
        fn parse_sub_tlv() {
            let mut outter_raw_data: [u8; 2 * Tlv::FtlSize + 12] = [0; 2 * Tlv::FtlSize + 12];
            outter_raw_data[0] = 0x20;
            outter_raw_data[1] = 0x02;
            outter_raw_data[2..4].copy_from_slice(&u16::to_be_bytes((Tlv::FtlSize + 12) as u16));

            let mut inner_raw_data: [u8; Tlv::FtlSize + 12] = [0; Tlv::FtlSize + 12];

            // TLV Flag
            inner_raw_data[4] = 0x20;
            // TLV Type
            inner_raw_data[5] = 0xfe;
            // TLV Length: There are only 8 bytes in the "value" of the Tlv, but we say that there are 9.
            inner_raw_data[6..8].copy_from_slice(&u16::to_be_bytes(9));
            // TLV Data
            inner_raw_data[8..16].copy_from_slice(&u64::to_be_bytes(0));

            outter_raw_data[4..].copy_from_slice(&inner_raw_data);

            let mut handler = LocationTlv {};
            let arguments: TestArguments = Default::default();
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5001);
            let tlv = TryInto::<Tlv>::try_into(outter_raw_data.as_slice())
                .expect("Outter TLV should parse");

            let logger = create_test_logger();
            let mut netconfig = netconf::NetConfiguration::new();

            let mut test_session_data: Option<SessionData> = None;

            let handled = handler
                .handle(
                    &tlv,
                    &arguments,
                    &mut netconfig,
                    address.into(),
                    &mut test_session_data,
                    logger,
                )
                .expect("Inner TLV should parse");

            let reparsed_sub_tlv = TryInto::<Tlv>::try_into(&handled.value.as_slice()[4..])
                .expect_err("Handled TLV should _not_ reparse");

            assert!(matches!(reparsed_sub_tlv, tlv::Error::NotEnoughData));
            assert!(handled.value[4] & 0x40 != 0);
        }

        #[test]
        fn parse_return_path_sub_tlv_single_address() {
            let bytes: Vec<u8> = vec![0x80, 0xa, 0, 8, 0x80, 2, 0, 4, 8, 8, 8, 8];
            let tlv = TryInto::<Tlv>::try_into(bytes.as_slice())
                .expect("Should be able to parse the raw bytes into a TLV");
            let sub_tlvs = TryInto::<ReturnPathTlv>::try_into(&tlv)
                .expect("Should be able to parse TLV into return path TLV");
            assert_eq!(sub_tlvs.address, Some(Into::<IpAddr>::into([8, 8, 8, 8])));
        }

        #[test]
        fn parse_return_path_sub_tlv_multiple_addresses() {
            let bytes: Vec<u8> = vec![
                0x80, 0xa, 0, 16, 0x80, 2, 0, 4, 8, 8, 8, 8, 0x80, 2, 0, 4, 8, 8, 8, 8,
            ];
            let tlv = TryInto::<Tlv>::try_into(bytes.as_slice())
                .expect("Should be able to parse the raw bytes into a TLV");
            let sub_tlvs = TryInto::<ReturnPathTlv>::try_into(&tlv);
            assert!(sub_tlvs.is_err());

            matches!(sub_tlvs.unwrap_err(), StampError::MalformedTlv(_));
        }
    }
}

pub struct CustomHandlers {}

impl CustomHandlers {
    pub fn build() -> handlers::Handlers {
        let mut handlers = handlers::Handlers::new();
        let time_handler = Arc::new(Mutex::new(ch::TimeTlv {}));
        handlers.add(time_handler);
        let dst_port_tlv: ch::DestinationPortTlv = Default::default();
        let destination_port_handler = Arc::new(Mutex::new(dst_port_tlv));
        handlers.add(destination_port_handler);
        let dst_address_tlv: ch::DestinationAddressTlv = Default::default();
        let destination_address_handler = Arc::new(Mutex::new(dst_address_tlv));
        handlers.add(destination_address_handler);
        let cos_tlv: ch::ClassOfServiceTlv = Default::default();
        let cos_handler = Arc::new(Mutex::new(cos_tlv));
        handlers.add(cos_handler);
        let location_handler = Arc::new(Mutex::new(ch::LocationTlv {}));
        handlers.add(location_handler);
        let unrecognized_handler = Arc::new(Mutex::new(ch::UnrecognizedTlv {}));
        handlers.add(unrecognized_handler);
        let padding_handler = Arc::new(Mutex::new(ch::PaddingTlv {}));
        handlers.add(padding_handler);
        let access_report_handler = Arc::new(Mutex::new(ch::AccessReportTlv {}));
        handlers.add(access_report_handler);
        let history_handler = Arc::new(Mutex::new(ch::HistoryTlv {}));
        handlers.add(history_handler);
        let followup_handler = Arc::new(Mutex::new(ch::FollowupTlv {}));
        handlers.add(followup_handler);
        let reflected_control_tlv: ch::ReflectedControlTlv = Default::default();
        let reflected_control_handler = Arc::new(Mutex::new(reflected_control_tlv));
        handlers.add(reflected_control_handler);
        let hmac_tlv: ch::HmacTlv = Default::default();
        let hmac_tlv_handler = Arc::new(Mutex::new(hmac_tlv));
        handlers.add(hmac_tlv_handler);
        let ber_tlv: ch::BitErrorRateTlv = Default::default();
        let ber_tlv_handler = Arc::new(Mutex::new(ber_tlv));
        handlers.add(ber_tlv_handler);
        let header_options_tlv: ch::V6ExtensionHeadersReflectionTlv = Default::default();
        let header_options_tlv_handler = Arc::new(Mutex::new(header_options_tlv));
        handlers.add(header_options_tlv_handler);
        let return_path_tlv_handler = Arc::new(Mutex::new(ch::ReturnPathTlv::default()));
        handlers.add(return_path_tlv_handler);
        handlers
    }
}
