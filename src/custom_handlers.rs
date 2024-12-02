use std::sync::{Arc, Mutex};

use crate::handlers;

pub mod ch {
    use std::{
        net::{SocketAddrV4, UdpSocket},
        thread,
    };

    use nix::sys::socket::{sockopt::Ipv4Tos, SetSockOpt, SockaddrIn};
    use slog::{error, info, Logger};

    use crate::{
        handlers::TlvHandler,
        parameters::{DscpValue, EcnValue, TestArgumentKind, TestArguments},
        stamp::{StampError, StampMsg},
        tlv::{self, Flags, Tlv},
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
            _client: SockaddrIn,
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
            address: SockaddrIn,
            logger: Logger,
        ) -> SockaddrIn {
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

            for tlv in response.tlvs.iter_mut() {
                if tlv.tpe == self.tlv_type() {
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
                        // TODO!
                    }
                    tlv.value[2] = 0x80;
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
            _client: SockaddrIn,
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
            address: SockaddrIn,
            logger: Logger,
        ) -> SockaddrIn {
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
                tpe: 177,
                length: 4,
                value: data.to_vec(),
            }
        }

        fn handle(
            &self,
            _tlv: &tlv::Tlv,
            _parameters: &TestArguments,
            _client: SockaddrIn,
            logger: slog::Logger,
        ) -> Result<Tlv, StampError> {
            info!(logger, "I am handling a destination port Tlv.");
            Ok(_tlv.clone())
        }

        fn prepare_response_target(
            &self,
            response: &mut StampMsg,
            address: SockaddrIn,
            logger: Logger,
        ) -> SockaddrIn {
            info!(
                logger,
                "Preparing the response target in the destination port Tlv."
            );
            for tlv in response.tlvs.iter() {
                if tlv.tpe == self.tlv_type() {
                    let new_port: u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                    let mut ipv4: SocketAddrV4 = address.into();
                    ipv4.set_port(new_port);
                    return ipv4.into();
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

        handlers
    }
}
