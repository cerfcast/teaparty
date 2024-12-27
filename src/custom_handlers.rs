use std::sync::{Arc, Mutex};

use crate::handlers;

pub mod ch {
    use std::net::{SocketAddr, UdpSocket};

    use nix::sys::socket::{sockopt::Ipv4Tos, SetSockOpt};
    use slog::{error, info, Logger};

    use crate::{
        handlers::TlvHandler,
        parameters::{DscpValue, EcnValue, TestArgumentKind, TestArguments},
        stamp::{StampError, StampMsg},
        tlv::{self, Flags, Tlv, Tlvs},
    };

    pub struct DscpEcnTlv {}

    impl TlvHandler for DscpEcnTlv {
        fn tlv_type(&self) -> u8 {
            Tlv::DSCPECN
        }

        fn tlv_name(&self) -> String {
            "dscpecn".into()
        }

        fn request(&self, _: Option<TestArguments>) -> Tlv {
            Tlv {
                flags: Flags::new_request(),
                tpe: self.tlv_type(),
                length: 4,
                value: vec![(0x2e << 2) | 1u8, 0, 0, 0],
            }
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

    impl TlvHandler for TimeTlv {
        fn tlv_type(&self) -> u8 {
            Tlv::TIMESTAMP
        }

        fn tlv_name(&self) -> String {
            "timestamp".into()
        }

        fn request(&self, _: Option<TestArguments>) -> Tlv {
            Tlv {
                flags: Flags::new_request(),
                tpe: 0x3,
                length: 4,
                value: vec![0u8; 4],
            }
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

    impl TlvHandler for DestinationPort {
        fn tlv_type(&self) -> u8 {
            Tlv::DESTINATION_PORT
        }

        fn tlv_name(&self) -> String {
            "destinationport".into()
        }

        fn request(&self, _: Option<TestArguments>) -> Tlv {
            let mut data = [0u8; 4];

            data[0..2].copy_from_slice(&983u16.to_be_bytes());

            Tlv {
                flags: Flags::new_request(),
                tpe: self.tlv_type(),
                length: 4,
                value: data.to_vec(),
            }
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

    impl TlvHandler for ClassOfServiceTlv {
        fn tlv_type(&self) -> u8 {
            Tlv::COS
        }

        fn tlv_name(&self) -> String {
            "classofservice".into()
        }

        fn request(&self, args: Option<TestArguments>) -> Tlv {
            let data = if let Some(tas) = args {
                let mut data = [0u8; 4];
                if let Ok(dscp_value) = tas.get_parameter_value::<u8>(TestArgumentKind::Dscp) {
                    data[0] = dscp_value << 2;
                }
                data
            } else {
                [0u8; 4]
            };

            Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::COS,
                length: 4,
                value: data.to_vec(),
            }
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

        handlers
    }
}
