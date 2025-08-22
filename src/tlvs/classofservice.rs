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
use slog::{error, info, Logger};

use crate::{
    handlers::{
        TlvHandler, TlvHandlerGenerator, TlvReflectorHandler, TlvRequestResult, TlvSenderHandler,
    },
    ip::{DscpValue, EcnValue},
    netconf::{
        NetConfiguration, NetConfigurationArgument, NetConfigurationItem, NetConfigurationItemKind,
    },
    parameters::{TestArgumentKind, TestArguments},
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

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
        let dscp2: DscpValue = (((tlv.value[0] & 0x3) << 4) | (tlv.value[1] >> 4)).try_into()?;
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

impl TlvReflectorHandler for ClassOfServiceTlv {
    fn tlv_name(&self) -> String {
        "Class of Service".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::COS].to_vec()
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

        let ecn_argument: u8 = match parameters.get_parameter_value::<u8>(TestArgumentKind::Ecn) {
            Ok(ecn_arguments) => ecn_arguments[0],
            Err(e) => return Err(e),
        };

        // Remember: DSCP bits are in the msb!
        let dscp_argument: u8 = match parameters.get_parameter_value::<u8>(TestArgumentKind::Dscp) {
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
}

impl TlvHandler for ClassOfServiceTlv {
    fn handle_netconfig_error(
        &mut self,
        response: &mut StampMsg,
        _socket: &UdpSocket,
        item: NetConfigurationItem,
        logger: Logger,
    ) {
        for tlv in &mut response.tlvs.tlvs {
            if self.tlv_sender_type().contains(&tlv.tpe) {
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

impl TlvSenderHandler for ClassOfServiceTlv {
    fn tlv_name(&self) -> String {
        "Class of Service".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        ClassOfServiceTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
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
}

pub struct ClassOfServiceTlvReflectorConfig {}

impl TlvHandlerGenerator for ClassOfServiceTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "class-of-service".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandler + Send> {
        Box::new(ClassOfServiceTlv::default())
    }
}

#[cfg(test)]
mod class_of_service_tlv_tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::{
        handlers::TlvReflectorHandler,
        netconf::NetConfiguration,
        parameters::{TestArgument, TestArguments},
        server::SessionData,
        tlv::{Flags, Tlv},
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
}
