use std::sync::{Arc, Mutex};

use crate::handlers;

pub mod ch {
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
    use nix::sys::socket::{sockopt::Ipv4Tos, SetSockOpt};
    use slog::{error, info, warn, Logger};

    use crate::{
        handlers::{TlvHandler, TlvRequestResult},
        parameters::{DscpValue, EcnValue, TestArgumentKind, TestArguments},
        stamp::{StampError, StampMsg},
        tlv::{self, Flags, Tlv, Tlvs},
    };

    pub struct DscpEcnTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum DscpEcnTlvCommand {
        DscpEcn {
            #[arg(last = true)]
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for DscpEcnTlv {
        fn tlv_cli_command(&self, command: Command) -> Command {
            DscpEcnTlvCommand::augment_subcommands(command)
        }

        fn tlv_type(&self) -> u8 {
            Tlv::DSCPECN
        }

        fn request(&self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
            let maybe_our_command = DscpEcnTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let DscpEcnTlvCommand::DscpEcn { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
            } else {
                None
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4,
                    value: vec![(0x2e << 2) | 1u8, 0, 0, 0],
                },
                remainder,
            ))
        }

        fn handle(
            &self,
            _tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _client: SocketAddr,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am in the Ecn TLV handler!");

            let ecn_argument: u8 = _parameters.get_parameter_value(TestArgumentKind::Ecn)?;
            let dscp_argument: u8 = _parameters.get_parameter_value(TestArgumentKind::Dscp)?;

            info!(logger, "Got ecn argument: {:x}", ecn_argument);
            info!(logger, "Got dscp argument: {:x}", dscp_argument);

            let dscp_ecn_response = (dscp_argument << 2) | ecn_argument;

            let ecn_requested_response: EcnValue = (_tlv.value[0] & 0x3).into();
            let dscp_requested_response: DscpValue = (_tlv.value[0] & 0xfc).into();

            info!(logger, "Ecn requested back? {:?}", ecn_requested_response);
            info!(logger, "Dscp requested back? {:?}", dscp_requested_response);
            info!(logger, "Response flags? {:?}", Flags::new_response());

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: self.tlv_type(),
                length: 4,
                value: vec![_tlv.value[0], dscp_ecn_response, 0, 0],
            };
            Ok(response)
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

        fn prepare_response_socket(
            &self,
            response: &mut StampMsg,
            socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Preparing the response socket in the Dscp Ecn Tlv.");

            for tlv in response.tlvs.tlvs.iter_mut() {
                if tlv.tpe == self.tlv_type() {
                    // TODO: Decide whether multiple handlers that may set the same byte of the header
                    // are cumulative.
                    let set_tos_value = tlv.value[0] as i32;
                    if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_tos_value) {
                        error!(
                            logger,
                            "There was an error preparing the response socket: {}",
                            set_tos_value_err
                        );
                        // This is not an error. All that we need to do is make sure that the RP
                        // field is set to 1 to indicate that we were not allowed to assign
                        // the requested DSCP/ECN values to the socket.
                        tlv.value[2] = 0x80;
                    }
                    return Ok(());
                }
            }
            Ok(())
        }

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(
                logger,
                "Unpreparing the response socket in the Dscp Ecn Tlv."
            );
            // TODO: We assume that the the unprepared socket has 0 for the tos byte -- that assumption
            // may not be correct!
            let set_tos_value = 0i32;
            if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_tos_value) {
                error!(
                    logger,
                    "There was an error unpreparing the response socket: {}", set_tos_value_err
                );
                return Err(Into::<StampError>::into(Into::<std::io::Error>::into(
                    std::io::ErrorKind::ConnectionRefused,
                )));
            }
            Ok(())
        }
    }

    pub struct TimeTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum TimeTlvCommand {
        Time {
            #[arg(last = true)]
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for TimeTlv {
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
            let TimeTlvCommand::Time { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
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
                remainder,
            ))
        }

        fn handle(
            &self,
            _tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _client: SocketAddr,
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

        fn prepare_response_socket(
            &self,
            _: &mut StampMsg,
            _: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(
                logger,
                "Preparing the response socket in the Timestamp Tlv."
            );
            Ok(())
        }

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            _: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Unpreparing the response socket in the Time Tlv.");
            Ok(())
        }
    }

    pub struct DestinationPort {}

    #[derive(Subcommand, Clone, Debug)]
    enum DestinationPortTlvCommand {
        DestinationPort {
            #[arg(last = true)]
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for DestinationPort {
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
            let DestinationPortTlvCommand::DestinationPort { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
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
                remainder,
            ))
        }

        fn handle(
            &self,
            _tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _client: SocketAddr,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am handling a destination port Tlv.");
            Ok(_tlv.clone())
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

        fn prepare_response_socket(
            &self,
            _: &mut StampMsg,
            _: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Preparing the response socket in the Time Tlv.");
            Ok(())
        }

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            _: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Unpreparing the response socket in the Time Tlv.");
            Ok(())
        }
    }

    pub struct ClassOfServiceTlv {}

    #[derive(Subcommand, Clone, Debug)]
    enum ClassOfServiceTlvCommand {
        ClassOfService {
            #[arg(last = true)]
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for ClassOfServiceTlv {
        fn tlv_cli_command(&self, existing: Command) -> Command {
            ClassOfServiceTlvCommand::augment_subcommands(existing)
        }

        fn tlv_type(&self) -> u8 {
            Tlv::COS
        }

        fn request(
            &self,
            args: Option<TestArguments>,
            matches: &mut ArgMatches,
        ) -> TlvRequestResult {
            let maybe_our_command = ClassOfServiceTlvCommand::from_arg_matches(matches);
            if maybe_our_command.is_err() {
                return None;
            }
            let our_command = maybe_our_command.unwrap();
            let ClassOfServiceTlvCommand::ClassOfService { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
            } else {
                None
            };

            let data = if let Some(tas) = args {
                let mut data = [0u8; 4];
                if let Ok(dscp_value) = tas.get_parameter_value::<u8>(TestArgumentKind::Dscp) {
                    data[0] = dscp_value << 2;
                }
                data
            } else {
                [0u8; 4]
            };

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: Tlv::COS,
                    length: 4,
                    value: data.to_vec(),
                },
                remainder,
            ))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            parameters: &TestArguments,
            _client: SocketAddr,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am in the Class of Service TLV handler!");

            if tlv.length != 4 {
                return Err(StampError::MalformedTlv(tlv::Error::NotEnoughData));
            }

            if tlv.value[1] & 0x3 != 0 {
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "RP".to_string(),
                )));
            }

            if tlv.value[2] != 0 || tlv.value[3] != 0 {
                return Err(StampError::MalformedTlv(tlv::Error::FieldNotZerod(
                    "Reserved".to_string(),
                )));
            }

            let ecn_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Ecn)?;
            let dscp_argument: u8 = parameters.get_parameter_value(TestArgumentKind::Dscp)?;

            info!(logger, "Got ecn argument: {:x}", ecn_argument);
            info!(logger, "Got dscp argument: {:x}", dscp_argument);

            let dscp_byte1 = tlv.value[0] | (dscp_argument >> 4);
            let dscp_byte2 = (dscp_argument << 4) | (ecn_argument << 2);

            info!(logger, "dscp_byte1: {:x}", dscp_byte1);
            info!(logger, "dscp_byte2: {:x}", dscp_byte2);

            let response = Tlv {
                flags: Flags::new_response(),
                tpe: self.tlv_type(),
                length: 4,
                value: vec![dscp_byte1, dscp_byte2, 0, 0],
            };
            Ok(response)
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

        fn prepare_response_socket(
            &self,
            response: &mut StampMsg,
            socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Preparing the response socket in the CoS Tlv.");

            for tlv in response.tlvs.tlvs.iter_mut() {
                if tlv.tpe == self.tlv_type() {
                    // TODO: Decide whether multiple handlers that may set the same byte of the header
                    // are cumulative.
                    let set_dscp_value = (tlv.value[0] & 0xfc) as i32;
                    if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_dscp_value) {
                        error!(
                            logger,
                            "There was an error preparing the response socket: {}",
                            set_tos_value_err
                        );
                        // This is not an error. All that we need to do is make sure that the RP
                        // field is set to 1 to indicate that we were not allowed to assign
                        // the requested DSCP value to the socket.
                        tlv.value[1] |= 0x1;
                    }
                    return Ok(());
                }
            }
            Ok(())
        }

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(logger, "Unpreparing the response socket in the CoS Tlv.");
            let set_tos_value = 0i32;
            // TODO: We assume that the the unprepared socket has 0 for the tos byte -- that assumption
            // may not be correct!
            if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_tos_value) {
                error!(
                    logger,
                    "There was an error unpreparing the response socket: {}", set_tos_value_err
                );
                return Err(Into::<StampError>::into(Into::<std::io::Error>::into(
                    std::io::ErrorKind::ConnectionRefused,
                )));
            }
            Ok(())
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
    }

    #[derive(Subcommand, Clone, Debug)]
    enum LocationTlvCommand {
        Location {
            #[arg(last = true)]
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for LocationTlv {
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
            let LocationTlvCommand::Location { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
            } else {
                None
            };

            let sub_tlv = Tlv {
                flags: Flags::new_request(),
                tpe: Self::SOURCE_IP_TYPE,
                length: Self::SOURCE_IP_LENGTH,
                value: vec![0u8; Self::SOURCE_IP_LENGTH as usize],
            };

            let mut request_value = vec![0u8, 0, 0, 0];
            let sub_tlv_value: Vec<u8> = sub_tlv.into();
            request_value.extend_from_slice(&sub_tlv_value);

            Some((
                Tlv {
                    flags: Flags::new_request(),
                    tpe: self.tlv_type(),
                    length: 4 + 20,
                    value: request_value,
                },
                remainder,
            ))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            client: SocketAddr,
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
                                Self::SOURCE_IP_LENGTH as usize,
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
                            }
                            IpAddr::V6(_) => {
                                panic!("Ipv6 is not yet supported");
                            }
                        }
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

        fn prepare_response_socket(
            &self,
            response: &mut StampMsg,
            socket: &UdpSocket,
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

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            _socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(
                logger,
                "Unpreparing the response socket in the Location Tlv."
            );
            Ok(())
        }
    }

    #[cfg(test)]
    mod stamp_handler_test_support {
        use slog::{Drain, Logger};

        pub fn create_test_logger() -> Logger {
            let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
            let drain = slog_term::FullFormat::new(decorator)
                .build()
                .filter_level(slog::Level::Debug)
                .fuse();
            slog::Logger::root(drain, slog::o!("version" => "0.5"))
        }
    }
    #[cfg(test)]
    mod stamp_location_tlv_handler {
        use std::net::{Ipv4Addr, SocketAddrV4};

        use crate::{
            custom_handlers::ch::LocationTlv,
            handlers::TlvHandler,
            parameters::TestArguments,
            tlv::{self, Tlv},
        };

        use super::stamp_handler_test_support::create_test_logger;

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
            let handled = handler
                .handle(&tlv, &arguments, address.into(), logger)
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
            remainder: Vec<String>,
        },
    }

    impl TlvHandler for UnrecognizedTlv {
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
            let UnrecognizedTlvCommand::Unrecognized { remainder } = our_command;
            let remainder = if !remainder.is_empty() {
                Some(remainder.join(" "))
            } else {
                None
            };

            Some((Tlv::unrecognized(32), remainder))
        }

        fn handle(
            &self,
            tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _client: SocketAddr,
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

        fn prepare_response_socket(
            &self,
            _response: &mut StampMsg,
            _socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(
                logger,
                "Preparing the response socket in the Unrecognized Tlv."
            );
            Ok(())
        }

        fn unprepare_response_socket(
            &self,
            _: &StampMsg,
            _socket: &UdpSocket,
            logger: Logger,
        ) -> Result<(), StampError> {
            info!(
                logger,
                "Unpreparing the response socket in the Unrecognized Tlv."
            );
            Ok(())
        }
    }
}

pub struct CustomHandlers {}

impl CustomHandlers {
    pub fn build() -> handlers::Handlers {
        let mut handlers = handlers::Handlers::new();
        let ecn_handler = Arc::new(Mutex::new(ch::DscpEcnTlv {}));
        handlers.add(ecn_handler);
        let time_handler = Arc::new(Mutex::new(ch::TimeTlv {}));
        handlers.add(time_handler);
        let destination_port_handler = Arc::new(Mutex::new(ch::DestinationPort {}));
        handlers.add(destination_port_handler);
        let cos_handler = Arc::new(Mutex::new(ch::ClassOfServiceTlv {}));
        handlers.add(cos_handler);
        let location_handler = Arc::new(Mutex::new(ch::LocationTlv {}));
        handlers.add(location_handler);
        let unrecognized_handler = Arc::new(Mutex::new(ch::UnrecognizedTlv {}));
        handlers.add(unrecognized_handler);

        handlers
    }
}
