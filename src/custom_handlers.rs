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

use std::sync::{Arc, Mutex};

use crate::handlers;

// Allow dead code in here because it is an API and, yes, there
// are fields that are not read ... yet.
#[allow(dead_code)]
pub mod ch {
    use std::{
        net::{IpAddr, SocketAddr, UdpSocket},
        sync::Arc,
        time::{Duration, Instant},
    };

    use clap::{ArgMatches, Command, FromArgMatches, Subcommand, ValueEnum};
    use slog::{error, info, warn, Logger};

    use crate::{
        asymmetry::{Asymmetry, TaskResult},
        handlers::{HandlerError, TlvHandler, TlvRequestResult},
        ip::{DscpValue, EcnValue},
        netconf::{NetConfiguration, NetConfigurationItem, NetConfigurationItemKind},
        ntp::TimeSource,
        parameters::{TestArgumentKind, TestArguments},
        responder::Responder,
        server::{Session, SessionData, Sessions},
        stamp::{StampError, StampMsg},
        tlv::{self, Flags, Tlv, Tlvs},
    };

    pub struct DscpEcnTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum DscpEcnTlvCommand {
        DscpEcn {
            #[arg(long, default_value = "ect0")]
            ecn: EcnValue,

            #[arg(long, default_value = "cs1")]
            dscp: DscpValue,

            #[arg(last = true)]
            next_tlv_command: Vec<String>,
        },
    }

    impl TlvHandler for DscpEcnTlv {
        fn tlv_name(&self) -> String {
            "DSCP ECN".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            DscpEcnTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> u8 {
            Tlv::DSCPECN
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = DscpEcnTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let DscpEcnTlvCommand::DscpEcn {
                ecn: user_ecn,
                dscp: user_dscp,
                next_tlv_command,
            } = our_command;

            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4,
                    value: vec![
                        Into::<u8>::into(user_dscp) | Into::<u8>::into(user_ecn),
                        0,
                        0,
                        0,
                    ],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            parameters: &TestArguments,
            netconfig: &mut NetConfiguration,
            _client: SocketAddr,
            _session: &mut Option<SessionData>,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am in the Ecn TLV handler!");

            let ecn_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Ecn)?;
            let dscp_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Dscp)?;

            info!(logger, "Got ecn argument: {:x}", ecn_argument);
            info!(logger, "Got dscp argument: {:x}", dscp_argument);

            let dscp_ecn_response = dscp_argument | ecn_argument;

            let ecn_requested_response: EcnValue = (tlv.value[0] & 0x3).into();
            let dscp_requested_response: DscpValue = ((tlv.value[0] & 0xfc) >> 2).into();

            info!(logger, "Ecn requested back? {:?}", ecn_requested_response);
            info!(logger, "Dscp requested back? {:?}", dscp_requested_response);
            info!(logger, "Response flags? {:?}", Flags::new_response());

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: self.tlv_type(),
                length: 4,
                value: vec![tlv.value[0], dscp_ecn_response, 0, 0],
            };

            let ecn_netconfig = NetConfigurationItem::Ecn(ecn_requested_response);
            let dscp_netconfig = NetConfigurationItem::Dscp(dscp_requested_response);

            netconfig.add_configuration(
                NetConfigurationItemKind::Dscp,
                dscp_netconfig,
                self.tlv_type(),
            );
            netconfig.add_configuration(
                NetConfigurationItemKind::Ecn,
                ecn_netconfig,
                self.tlv_type(),
            );

            Ok(response)
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the Dscp Ecn Tlv.");
            address
        }
        fn handle_netconfig_error(
            &self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            item: NetConfigurationItem,
            logger: Logger,
        ) {
            error!(logger, "There was an error doing DSCP/ECN net configuration on reflected packet. Updating RP value. (DSCP ECN Handler)");
            match item {
                NetConfigurationItem::Dscp(_) | NetConfigurationItem::Ecn(_) => {
                    for tlv in &mut response.tlvs.tlvs {
                        if tlv.tpe == self.tlv_type() {
                            // Adjust our response to indicate that there was an error
                            // setting the requested parameters on the packet!
                            tlv.value[2] |= 0x1 << 6;
                        }
                    }
                }
                _ => {}
            }
        }
    }

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

        fn tlv_type(&self) -> u8 {
            Tlv::TIMESTAMP
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = TimeTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let TimeTlvCommand::Time { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: 0x3,
                    length: 4,
                    value: vec![0u8; 4],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(
                logger,
                "Preparing the response target in the Timestamp Tlv."
            );
            address
        }
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

    #[derive(Default, Debug)]
    pub struct DestinationPortTlv {
        pub port: u16,
    }

    impl TryFrom<&Tlv> for DestinationPortTlv {
        type Error = StampError;
        fn try_from(value: &Tlv) -> Result<Self, Self::Error> {
            if value.length != 4 {
                return Err(StampError::MalformedTlv(tlv::Error::NotEnoughData));
            }
            let port: u16 = u16::from_be_bytes(value.value[0..2].try_into().map_err(|_| {
                StampError::MalformedTlv(tlv::Error::FieldValueInvalid(
                    "Could not extract port number from TLV value.".to_string(),
                ))
            })?);
            Ok(Self { port })
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum DestinationPortTlvCommand {
        DestinationPort {
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
        fn tlv_type(&self) -> u8 {
            Tlv::DESTINATION_PORT
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = DestinationPortTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let DestinationPortTlvCommand::DestinationPort { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            let mut data = [0u8; 4];

            data[0..2].copy_from_slice(&983u16.to_be_bytes());

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4,
                    value: data.to_vec(),
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            response: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(
                logger,
                "Preparing the response target in the destination port Tlv."
            );
            for tlv in response.tlvs.tlvs.iter() {
                if tlv.tpe == self.tlv_type() {
                    let new_port: u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                    let mut ipv4 = address;
                    ipv4.set_port(new_port);
                    return ipv4;
                }
            }
            address
        }

        fn handle_netconfig_error(
            &self,
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
        dscp1: DscpValue,
        dscp2: DscpValue,
        ecn1: EcnValue,
        ecn2: EcnValue,
        rp: u8,
    }

    impl TryFrom<&Tlv> for ClassOfServiceTlv {
        type Error = StampError;
        fn try_from(tlv: &Tlv) -> Result<ClassOfServiceTlv, StampError> {
            if tlv.length != 4 {
                return Err(StampError::MalformedTlv(tlv::Error::NotEnoughData));
            }

            if tlv.value[2] & 0x3f != 0 || tlv.value[3] != 0 {
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "Reserved".to_string(),
                )));
            }

            let dscp1: DscpValue = ((tlv.value[0] & 0xfc) >> 2).into();
            let dscp2: DscpValue = (((tlv.value[0] & 0x3) << 4) | (tlv.value[1] >> 4)).into();
            let ecn1: EcnValue = ((tlv.value[1] & 0x0c) >> 2).into();
            let ecn2: EcnValue = ((tlv.value[2] & 0xc0) >> 6).into();
            let rp: u8 = tlv.value[1] & 0x3;

            Ok(Self {
                dscp1,
                dscp2,
                ecn1,
                ecn2,
                rp,
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
            let dscp_byte2 = (dscp2_b << 2) | (ecn1_b << 2) | value.rp & 0x3;
            let reserved_byte1 = ecn2_b << 6;

            vec![dscp_byte1, dscp_byte2, reserved_byte1, 0]
        }
    }

    #[derive(Subcommand, Clone, Debug)]
    enum ClassOfServiceTlvCommand {
        ClassOfService {
            #[arg(long, default_value = "cs1")]
            dscp: DscpValue,

            #[arg(long, default_value = "NotEct")]
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

        fn tlv_type(&self) -> u8 {
            Tlv::COS
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = ClassOfServiceTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::COS,
                    length: 4,
                    value: vec![
                        Into::<u8>::into(user_dscp),
                        0,
                        Into::<u8>::into(user_ecn) << 6,
                        0,
                    ],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            parameters: &TestArguments,
            netconfig: &mut NetConfiguration,
            _client: SocketAddr,
            _session: &mut Option<SessionData>,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am in the Class of Service TLV handler!");

            let mut cos_tlv: ClassOfServiceTlv = TryFrom::try_from(tlv)?;

            if cos_tlv.rp != 0 {
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "RP".to_string(),
                )));
            }

            let ecn_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Ecn)?;
            // Remember: DSCP bits are in the msb!
            let dscp_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Dscp)?;

            info!(logger, "Got ecn argument: {:x}", ecn_argument);
            info!(logger, "Got dscp argument: {:x}", dscp_argument);

            cos_tlv.ecn1 = ecn_argument.into();
            // Into from DscpValue to u8 assumes that the DSCP bits are in lsb.
            cos_tlv.dscp2 = (dscp_argument >> 2).into();

            if cos_tlv.ecn2 != EcnValue::NotEct {
                cos_tlv.rp = 0x2;
            }

            info!(logger, "Dscp requested back? {:?}", cos_tlv.dscp1);

            let dscp_netconfig = NetConfigurationItem::Dscp(cos_tlv.dscp1);
            netconfig.add_configuration(
                NetConfigurationItemKind::Dscp,
                dscp_netconfig,
                self.tlv_type(),
            );

            let ecn_netconfig = NetConfigurationItem::Ecn(cos_tlv.ecn2);
            netconfig.add_configuration(
                NetConfigurationItemKind::Ecn,
                ecn_netconfig,
                self.tlv_type(),
            );

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: self.tlv_type(),
                length: 4,
                value: cos_tlv.into(),
            };

            Ok(response)
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the CoS Tlv.");
            address
        }
        fn handle_netconfig_error(
            &self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            item: NetConfigurationItem,
            logger: Logger,
        ) {
            error!(logger, "There was an error doing DSCP/ECN net configuration on reflected packet. Updating RP value. (Class of Service Handler)");
            match item {
                NetConfigurationItem::Dscp(_) | NetConfigurationItem::Ecn(_) => {
                    for tlv in &mut response.tlvs.tlvs {
                        if tlv.tpe == self.tlv_type() {
                            // Adjust our response to indicate that there was an error
                            // setting the reverse path parameters on the packet!
                            tlv.value[1] |= 0x1;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    #[cfg(test)]
    mod stamp_class_of_service_tlv_handler_tests {
        use std::net::{Ipv4Addr, SocketAddrV4};

        use crate::{
            handlers::TlvHandler,
            netconf::NetConfiguration,
            parameters::{TestArgument, TestArguments},
            server::SessionData,
            tlv::{Flags, Tlv},
        };

        use crate::test::stamp_handler_test_support::create_test_logger;

        use super::ClassOfServiceTlv;

        #[test]
        fn simple_cos_handler_extract_pack_test() {
            let mut args = TestArguments::empty_arguments();

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

            let cos_handler: ClassOfServiceTlv = Default::default();

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
                0,
                0,
            ];

            assert!(result
                .value
                .iter()
                .zip(expected_result.iter())
                .all(|(l, r)| l == r));
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

        fn tlv_type(&self) -> u8 {
            Tlv::LOCATION
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = LocationTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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
                hmac_tlv: None,
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: request_value.len() as u16,
                    value: request_value,
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "Destination port".to_string(),
                )));
            }

            if src_port != 0 {
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "Source port".to_string(),
                )));
            }

            let start_offset = 4usize;
            let mut sub_tlvs: Tlvs = TryFrom::<&[u8]>::try_from(&tlv.value[start_offset..])?;

            for sub_tlv in sub_tlvs.tlvs.iter_mut() {
                if sub_tlv.value.iter().any(|f| *f != 0) {
                    return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                        format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                    )));
                }

                match sub_tlv.tpe {
                    Self::SOURCE_IP_TYPE => {
                        if sub_tlv.length != Self::SOURCE_IP_LENGTH {
                            return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
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
                            return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
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
                            return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
                                format!("Sub TLV with type {}", sub_tlv.tpe).to_string(),
                                Self::DESTINATION_IP_LENGTH as usize,
                                sub_tlv.length as usize,
                            )));
                        }
                        sub_tlv.flags.set_unrecognized(false);
                        sub_tlv.flags.set_malformed(false);
                        sub_tlv.flags.set_integrity(true);

                        sub_tlv.tpe = Self::SOURCE_EUI48_TYPE;

                        let peer_mac_address = _parameters
                            .get_parameter_value::<Vec<u8>>(TestArgumentKind::PeerMacAddress)
                            .unwrap();
                        info!(logger, "The location TLV is requesting a source mac address; responding with {:?}", peer_mac_address);

                        sub_tlv.value = peer_mac_address;
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
                tpe: self.tlv_type(),
                length: result_value.len() as u16,
                value: result_value,
            })
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the Location Tlv.");
            address
        }

        fn pre_send_fixup(
            &self,
            response: &mut StampMsg,
            socket: &UdpSocket,
            _session: &Option<SessionData>,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Preparing the response socket in the Location Tlv.");

            for tlv in response.tlvs.tlvs.iter_mut() {
                if tlv.tpe == self.tlv_type() {
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
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Location) that does not set net configuration items.");
        }
    }

    #[cfg(test)]
    mod stamp_location_tlv_handler_tests {
        use std::net::{Ipv4Addr, SocketAddrV4};

        use crate::{
            custom_handlers::ch::LocationTlv,
            handlers::TlvHandler,
            netconf,
            parameters::TestArguments,
            server::SessionData,
            tlv::{self, Tlv},
        };

        use crate::test::stamp_handler_test_support::create_test_logger;

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

            let handler = LocationTlv {};
            let arguments = TestArguments::empty_arguments();
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

        fn tlv_type(&self) -> u8 {
            0
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = UnrecognizedTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let UnrecognizedTlvCommand::Unrecognized { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Some((Tlv::unrecognized(32), next_tlv_command))
        }

        fn handle(
            &self,
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

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(
                logger,
                "Preparing the response target in the Unrecognized Ecn Tlv."
            );
            address
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }
        fn handle_netconfig_error(
            &self,
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

        fn tlv_type(&self) -> u8 {
            Tlv::PADDING
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = PaddingTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4 + size,
                    value: vec![0u8; 4 + size as usize],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the Padding Tlv.");
            address
        }

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
        type Error = tlv::Error;
        fn try_from(value: u8) -> Result<Self, Self::Error> {
            let value = value >> 4;
            if value == 1 {
                Ok(AccessReportAccessId::ThreeGPP)
            } else if value == 2 {
                Ok(AccessReportAccessId::NonThreeGPP)
            } else {
                Err(tlv::Error::FieldValueInvalid("Access ID".to_string()))
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

        fn tlv_type(&self) -> u8 {
            Tlv::ACCESSREPORT
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = AccessReportTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4,
                    value: vec![access_id.into(), active.into(), 0, 0],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
                return Err(StampError::MalformedTlv(tlv::Error::FieldValueInvalid(
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

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(
                logger,
                "Preparing the response target in the AccessReport Tlv."
            );
            address
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }
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

        fn tlv_type(&self) -> u8 {
            Tlv::HISTORY
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = HistoryTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: (length as u16) * Self::OCTETS_PER_ENTRY as u16,
                    value: vec![0u8; length * Self::OCTETS_PER_ENTRY],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
                tpe: self.tlv_type(),
                length: history_bytes.len() as u16,
                value: history_bytes,
            })
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the History Tlv.");
            address
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }
        fn handle_netconfig_error(
            &self,
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

        fn tlv_type(&self) -> u8 {
            Tlv::FOLLOWUP
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = FollowupTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let FollowupTlvCommand::Followup { next_tlv_command } = our_command;
            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: Self::TLV_LENGTH,
                    value: vec![0u8; Self::TLV_LENGTH as usize],
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _netconfig: &mut NetConfiguration,
            _client: SocketAddr,
            _session: &mut Option<SessionData>,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "Handling the response in the Followup Tlv.");

            if tlv.length != Self::TLV_LENGTH {
                return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
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
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the Followup Tlv.");
            address
        }

        fn handle_netconfig_error(
            &self,
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
                return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
                    "Length".to_string(),
                    Self::MINIMUM_LENGTH as usize,
                    value.value.len(),
                )));
            }
            let reflected_length: u16 =
                u16::from_be_bytes(value.value[0..2].try_into().map_err(|_| {
                    StampError::MalformedTlv(tlv::Error::FieldValueInvalid(
                        "reflected_length".to_string(),
                    ))
                })?);

            let count: u16 = u16::from_be_bytes(value.value[2..4].try_into().map_err(|_| {
                StampError::MalformedTlv(tlv::Error::FieldValueInvalid("count".to_string()))
            })?);

            let interval: u32 = u32::from_be_bytes(value.value[4..8].try_into().map_err(|_| {
                StampError::MalformedTlv(tlv::Error::FieldValueInvalid("interval".to_string()))
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

    fn parse_duration(duration_str: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
        let seconds: u64 = duration_str.parse()?;
        Ok(Duration::from_secs(seconds))
    }

    impl TlvHandler for ReflectedControlTlv {
        fn tlv_name(&self) -> String {
            "Reflected test packet control".into()
        }

        fn tlv_cli_command(&self, command: Command) -> Command {
            ReflectedControlTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> u8 {
            Tlv::REFLECTED_CONTROL
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = ReflectedControlTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
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

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: ReflectedControlTlv::MINIMUM_LENGTH,
                    value: ReflectedControlTlv {
                        reflected_length: user_reflected_length,
                        count: user_count,
                        interval: user_interval.as_nanos().try_into().unwrap(),
                    }
                    .into(),
                },
                next_tlv_command,
            ))
        }

        fn request_fixup(
            &self,
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
                    reflected_control_tlv_requested_length as usize - raw_packet_msg_length;

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
            &self,
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
                tpe: self.tlv_type(),
                length: Self::MINIMUM_LENGTH,
                value: reflected_control_tlv.into(),
            };
            Ok(response)
        }
        fn pre_send_fixup(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(
                logger,
                "Preparing the response target in the Reflected Test Packet Control TLV."
            );
            address
        }
        fn handle_netconfig_error(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (Reflected Test Packet Control TLV) that does not set net configuration items.");
        }

        fn handle_asymmetry(
            &self,
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
                if tlv.tpe == self.tlv_type() {
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
                        "I'm here because of a Reflected Test Packet Control TLV."
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

    #[cfg(test)]
    mod stamp_reflected_control_handler_tests {
        use crate::tlv::{Flags, Tlv};

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
                return Err(StampError::MalformedTlv(tlv::Error::WrongType(
                    Tlv::HMAC_TLV,
                    value.tpe,
                )));
            }

            if value.value.len() != Self::LENGTH as usize {
                return Err(StampError::MalformedTlv(tlv::Error::FieldWrongSized(
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

        fn tlv_type(&self) -> u8 {
            Tlv::HMAC_TLV
        }

        fn request_fixup(
            &self,
            request: &mut StampMsg,
            _session: &Option<SessionData>,
            logger: Logger,
        ) -> Result<(), StampError> {
            if let Some(hmac_tlv) = request.tlvs.hmac_tlv.clone() {
                if let Some(SessionData { key: Some(key), .. }) = _session {
                    let hmac = request.tlvs.hmac(request.sequence, key)?;
                    if hmac_tlv.value != hmac {
                        info!(logger, "Verification of the TLV HMAC on a received STAMP packet failed; expected {:x?} vs received {:x?}", hmac_tlv.value, hmac);
                        return Err(StampError::InvalidSignature);
                    }
                }
            }

            Ok(())
        }

        fn request(
            &self,
            _args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = HmacTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let HmacTlvCommand::Hmac { next_tlv_command } = our_command;

            let next_tlv_command = if !next_tlv_command.is_empty() {
                Some(next_tlv_command.join(" "))
            } else {
                None
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: HmacTlv::LENGTH,
                    value: HmacTlv { hmac: [0; 16] }.into(),
                },
                next_tlv_command,
            ))
        }

        fn handle(
            &self,
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
                tpe: self.tlv_type(),
                length: Self::LENGTH,
                value: hmac_tlv.into(),
            };
            Ok(response)
        }
        fn pre_send_fixup(
            &self,
            response: &mut StampMsg,
            _socket: &UdpSocket,
            session: &Option<SessionData>,
            _logger: Logger,
        ) -> Result<(), StampError> {
            if let Some(SessionData {
                sequence: _,
                reference_count: _,
                last: _,
                key: Some(key),
                history: _,
            }) = session
            {
                if response.tlvs.hmac_tlv.is_some() {
                    let hmac = response.tlvs.hmac(response.sequence, key)?;
                    response.tlvs.hmac_tlv.as_mut().unwrap().value = hmac;
                }
            }
            Ok(())
        }

        fn prepare_response_target(
            &self,
            _: &mut StampMsg,
            address: SocketAddr,
            logger: Logger,
        ) -> SocketAddr {
            info!(logger, "Preparing the response target in the HMAC TLV.");
            address
        }
        fn handle_netconfig_error(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            _item: NetConfigurationItem,
            _logger: Logger,
        ) {
            panic!("There was a net configuration error in a handler (HMAC TLV) that does not set net configuration items.");
        }
    }

    #[cfg(test)]
    mod stamp_hmac_tlv_handler_tests {
        use crate::{
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
    }
}

use ch::{ClassOfServiceTlv, DestinationPortTlv, HmacTlv, ReflectedControlTlv};
pub struct CustomHandlers {}

impl CustomHandlers {
    pub fn build() -> handlers::Handlers {
        let mut handlers = handlers::Handlers::new();
        let ecn_handler = Arc::new(Mutex::new(ch::DscpEcnTlv {}));
        handlers.add(ecn_handler);
        let time_handler = Arc::new(Mutex::new(ch::TimeTlv {}));
        handlers.add(time_handler);
        let dst_port_tlv: DestinationPortTlv = Default::default();
        let destination_port_handler = Arc::new(Mutex::new(dst_port_tlv));
        handlers.add(destination_port_handler);
        let cos_tlv: ClassOfServiceTlv = Default::default();
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
        let reflected_control_tlv: ReflectedControlTlv = Default::default();
        let reflected_control_handler = Arc::new(Mutex::new(reflected_control_tlv));
        handlers.add(reflected_control_handler);
        let hmac_tlv: HmacTlv = Default::default();
        let hmac_tlv_handler = Arc::new(Mutex::new(hmac_tlv));
        handlers.add(hmac_tlv_handler);
        handlers
    }
}
