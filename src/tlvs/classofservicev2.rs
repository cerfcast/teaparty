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
        TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator,
        TlvRequestResult, TlvSenderHandler, TlvSenderHandlerConfigurator,
    },
    ip::{DscpValue, EcnValue},
    netconf::{
        NetConfiguration, NetConfigurationArgument, NetConfigurationItem, NetConfigurationItemKind,
        NetConfigurator,
    },
    parameters::{TestArgumentKind, TestArguments},
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

#[derive(Default, Debug)]
pub struct ClassOfServiceV2Tlv {
    // Value for DSCP set by the session sender
    dscpa: DscpValue,
    // Value for ECN set by the session sender
    ecna: EcnValue,
    //  Value for DSCP received by the session reflector
    dscpb: DscpValue,
    //  Value for ECN received by the session reflector
    ecnb: EcnValue,
    // Value for DSCP that session sender wants set in reflected packet
    dscpc: DscpValue,
    // Value for DSCP that session sender wants set in reflected packet
    ecnc: EcnValue,
    // Value for DSCP that session reflector set in reflected packet
    dscpd: DscpValue,
    // Value for ECN that session reflector set in reflected packet
    ecnd: EcnValue,
}

impl TryFrom<&Tlv> for ClassOfServiceV2Tlv {
    type Error = StampError;
    fn try_from(tlv: &Tlv) -> Result<ClassOfServiceV2Tlv, StampError> {
        if tlv.length != 4 {
            return Err(StampError::MalformedTlv(Error::NotEnoughData));
        }

        let dscpa: DscpValue = ((tlv.value[0] & 0xfc) >> 2).try_into()?;
        let dscpb: DscpValue = ((tlv.value[1] & 0xfc) >> 2).try_into()?;
        let dscpc: DscpValue = ((tlv.value[2] & 0xfc) >> 2).try_into()?;
        let dscpd: DscpValue = ((tlv.value[3] & 0xfc) >> 2).try_into()?;

        let ecna: EcnValue = (tlv.value[0] & 0x03).into();
        let ecnb: EcnValue = (tlv.value[1] & 0x03).into();
        let ecnc: EcnValue = (tlv.value[2] & 0x03).into();
        let ecnd: EcnValue = (tlv.value[3] & 0x03).into();

        Ok(Self {
            dscpa,
            ecna,
            dscpb,
            ecnb,
            dscpc,
            ecnc,
            dscpd,
            ecnd,
        })
    }
}

impl From<ClassOfServiceV2Tlv> for Vec<u8> {
    fn from(value: ClassOfServiceV2Tlv) -> Self {
        // Remember: Into trait will push the 6 bits of the DSCP into the msb!
        let b0: u8 = Into::<u8>::into(value.dscpa) | Into::<u8>::into(value.ecna);
        let b1: u8 = Into::<u8>::into(value.dscpb) | Into::<u8>::into(value.ecnb);
        let b2: u8 = Into::<u8>::into(value.dscpc) | Into::<u8>::into(value.ecnc);
        let b3: u8 = Into::<u8>::into(value.dscpd) | Into::<u8>::into(value.ecnd);

        vec![b0, b1, b2, b3]
    }
}

#[derive(Subcommand, Clone, Debug)]
enum ClassOfServiceV2TlvCommand {
    ClassOfServiceV2 {
        #[arg(long, default_value = "cs1")]
        dscp: DscpValue,

        #[arg(long, default_value = "not-ect")]
        ecn: EcnValue,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl TlvReflectorHandler for ClassOfServiceV2Tlv {
    fn tlv_name(&self) -> String {
        "Class of Service (v2)".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::COSV2].to_vec()
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
        let mut cosv2_tlv: ClassOfServiceV2Tlv = TryFrom::try_from(tlv)?;

        if cosv2_tlv.dscpb != DscpValue::CS0 {
            return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                "DSCPb".to_string(),
            )));
        }

        if cosv2_tlv.ecnb != EcnValue::NotEct {
            return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                "ECNb".to_string(),
            )));
        }

        if cosv2_tlv.dscpd != DscpValue::CS0 {
            return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                "DSCPd".to_string(),
            )));
        }

        if cosv2_tlv.ecnd != EcnValue::NotEct {
            return Err(StampError::MalformedTlv(Error::FieldNotZerod(
                "ECNd".to_string(),
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

        // Mark what we got!
        cosv2_tlv.ecnb = ecn_argument.into();
        // Into from DscpValue to u8 assumes that the DSCP bits are in lsb.
        cosv2_tlv.dscpb = (dscp_argument >> 2).try_into()?;

        info!(logger, "Dscp requested back? {:?}", cosv2_tlv.dscpc);
        info!(logger, "Ecn requested back? {:?}", cosv2_tlv.ecnc);

        netconfig.add_configuration(
            NetConfigurationItemKind::Dscp,
            NetConfigurationArgument::Dscp(cosv2_tlv.dscpc),
            Tlv::COSV2,
        );

        netconfig.add_configuration(
            NetConfigurationItemKind::Ecn,
            NetConfigurationArgument::Ecn(cosv2_tlv.ecnc),
            Tlv::COSV2,
        );

        // Set what we set.
        cosv2_tlv.ecnd = cosv2_tlv.ecnc;
        cosv2_tlv.dscpd = cosv2_tlv.dscpc;

        let response = Tlv {
            flags: Flags::new_response(),
            tpe: Tlv::COSV2,
            length: 4,
            value: cosv2_tlv.into(),
        };

        Ok(response)
    }
}

impl NetConfigurator for ClassOfServiceV2Tlv {
    fn handle_netconfig_error(
        &self,
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
                        error!(logger, "There was an error doing DSCP net configuration on reflected packet. Updating DSCPd. (Class of Service V2)");
                        tlv.value[3] &= 0x03;
                    }
                    NetConfigurationItem::Ecn(_) => {
                        error!(logger, "There was an error doing ECN net configuration on reflected packet. Updating ECNd value. (Class of Service V2)");
                        tlv.value[3] &= 0xfc;
                    }
                    _ => {}
                };
            }
        }
    }
}

impl TlvSenderHandler for ClassOfServiceV2Tlv {
    fn tlv_name(&self) -> String {
        "Class of Service (V2)".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        ClassOfServiceV2TlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::COSV2].to_vec()
    }

    fn request(
        &mut self,
        args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = ClassOfServiceV2TlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let ClassOfServiceV2TlvCommand::ClassOfServiceV2 {
            dscp: user_dscp,
            ecn: user_ecn,
            next_tlv_command,
        } = our_command;

        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        let (dscp_arg, ecn_arg) = if let Some(args) = args {
            let ecnv = if let Ok(ecn_raw) = args.get_parameter_value::<u8>(TestArgumentKind::Ecn) {
                Into::<EcnValue>::into(ecn_raw[0])
            } else {
                EcnValue::NotEct
            };
            let dscpv = if let Ok(dscp_raw) = args.get_parameter_value::<u8>(TestArgumentKind::Dscp)
            {
                TryInto::<DscpValue>::try_into(dscp_raw[0] >> 2).unwrap_or_default()
            } else {
                Default::default()
            };
            (dscpv, ecnv)
        } else {
            (DscpValue::CS0, EcnValue::NotEct)
        };

        let cosv2_tlv = ClassOfServiceV2Tlv {
            dscpa: dscp_arg,
            ecna: ecn_arg,
            dscpb: DscpValue::CS0,
            ecnb: EcnValue::NotEct,
            dscpc: user_dscp,
            ecnc: user_ecn,
            dscpd: DscpValue::CS0,
            ecnd: EcnValue::NotEct,
        };

        Ok(Some((
            [Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::COSV2,
                length: 4,
                value: cosv2_tlv.into(),
            }]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

impl TlvReflectorHandlerConfigurator for ClassOfServiceV2Tlv {}
impl TlvSenderHandlerConfigurator for ClassOfServiceV2Tlv {}

pub struct ClassOfServiceV2TlvReflectorConfig {}

impl TlvHandlerGenerator for ClassOfServiceV2TlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "class-of-servicev2".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(ClassOfServiceV2Tlv::default())
    }
}

#[cfg(test)]
mod class_of_service_tlv_tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::{
        handlers::TlvReflectorHandler,
        ip::{DscpValue, EcnValue},
        netconf::NetConfiguration,
        parameters::{TestArgument, TestArguments},
        server::SessionData,
        tlv::{Flags, Tlv},
    };

    use crate::test::stamp_handler_test_support::create_test_logger;

    use super::ClassOfServiceV2Tlv;

    #[test]
    fn simple_cosv2_from_test() {
        let tlv = Tlv {
            flags: Flags::new_request(),
            tpe: Tlv::COSV2,
            length: 4,
            value: [0xc1, 0x00, 0xe2, 0x00].to_vec(),
        };
        let cos_tlv: ClassOfServiceV2Tlv =
            TryFrom::try_from(&tlv).expect("Should be able to parse TLV into COS V2 TLV");

        assert!(cos_tlv.dscpa == DscpValue::CS6);
        assert!(cos_tlv.dscpc == DscpValue::CS7);
        assert!(cos_tlv.ecna == EcnValue::Ect1);
        assert!(cos_tlv.ecnc == EcnValue::Ect0);
    }

    #[test]
    fn simple_cosv2_into_test() {
        let cos_tlv = ClassOfServiceV2Tlv {
            dscpa: DscpValue::CS6,
            ecna: EcnValue::Ect1,
            dscpb: DscpValue::CS6,
            ecnb: EcnValue::Ect1,
            dscpc: DscpValue::CS6,
            ecnc: EcnValue::Ect1,
            dscpd: DscpValue::CS6,
            ecnd: EcnValue::Ect1,
        };
        let bytes = Into::<Vec<u8>>::into(cos_tlv);
        assert!(bytes == [0xc1, 0xc1, 0xc1, 0xc1].to_vec());
    }

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
            tpe: Tlv::COSV2,
            length: 4,
            value: vec![
                Into::<u8>::into(DscpValue::AF23) | Into::<u8>::into(EcnValue::NotEct),
                0,
                Into::<u8>::into(DscpValue::AF12) | Into::<u8>::into(EcnValue::Ect1),
                0,
            ],
        };

        let mut cos_handler: ClassOfServiceV2Tlv = Default::default();

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
            .expect("COSV2 handler should have worked");

        let expected_result = [
            Into::<u8>::into(DscpValue::AF23) | Into::<u8>::into(EcnValue::NotEct),
            Into::<u8>::into(DscpValue::AF23) | Into::<u8>::into(EcnValue::NotEct),
            Into::<u8>::into(DscpValue::AF12) | Into::<u8>::into(EcnValue::Ect1),
            Into::<u8>::into(DscpValue::AF12) | Into::<u8>::into(EcnValue::Ect1),
        ];

        assert!(result
            .value
            .iter()
            .zip(expected_result.iter())
            .all(|(l, r)| l == r));
    }
}
