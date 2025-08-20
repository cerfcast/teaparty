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

use crate::handlers::{TlvHandler, TlvHandlerGenerator, TlvReflectorHandler};

use std::net::{IpAddr, SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    ip::{MplsSegmentList, Srv6SegmentList},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Recognized, SubTlvInto, Tlv, Tlvs, Unrecognized},
};
use std::sync::{Arc, Mutex};

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
                            "Cannot specify a Return-Address Sub TLV more than once".to_string(),
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

impl TryFrom<ReturnPathTlv> for Tlvs {
    type Error = StampError;

    fn try_from(value: ReturnPathTlv) -> Result<Self, Self::Error> {
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

        Ok(sub_tlvs)
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
impl TlvReflectorHandler for ReturnPathTlv {
    fn tlv_name(&self) -> String {
        "Return Path".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::RETURN_PATH].to_vec()
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
        let result_tlv: Tlv =
            TryFrom::try_from(SubTlvInto::<Self, Recognized, { Tlv::RETURN_PATH }> {
                s: return_path_tlv,
                ..Default::default()
            })?;

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
}

impl TlvHandler for ReturnPathTlv {
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
impl TlvSenderHandler for ReturnPathTlv {
    fn tlv_name(&self) -> String {
        "Return Path".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        ReturnPathTlvCommand::augment_subcommands(existing)
    }
    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::RETURN_PATH].to_vec()
    }

    fn request(&mut self, _: Option<TestArguments>, matches: &mut ArgMatches) -> TlvRequestResult {
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
            [
                TryFrom::try_from(SubTlvInto::<Self, Unrecognized, { Tlv::RETURN_PATH }> {
                    s: return_path_tlv,
                    ..Default::default()
                })
                .map_err(|_| clap::Error::new(clap::error::ErrorKind::InvalidValue))?,
            ]
            .to_vec(),
            next_tlv_command,
        )))
    }
}

pub struct ReturnPathTlvReflectorConfig {}

impl TlvHandlerGenerator for ReturnPathTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "returnpath".into()
    }

    fn generate(&self) -> Arc<Mutex<dyn TlvReflectorHandler + Send>> {
        Arc::new(Mutex::new(ReturnPathTlv::default()))
    }

    fn configure(&self) {
        println!("Going to configure a reflected-control\n");
    }
}

#[cfg(test)]
mod return_path_tlv_tests {
    use std::net::IpAddr;

    use crate::{stamp::StampError, tlv::Tlv, tlvs::returnpath::ReturnPathTlv};

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
