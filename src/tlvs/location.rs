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
use slog::{info, warn, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::{TestArgumentKind, TestArguments},
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv, Tlvs},
};

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
impl TlvReflectorHandler for LocationTlv {
    fn tlv_name(&self) -> String {
        "Location".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::LOCATION].to_vec()
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
                    info!(
                        logger,
                        "The location TLV is requesting a source mac address; responding with {:?}",
                        peer_mac_address
                    );

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
                let mut sub_tlvs: Tlvs = TryFrom::<&[u8]>::try_from(&tlv.value[start_offset..])?;

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
}

impl TlvHandler for LocationTlv {
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
impl TlvSenderHandler for LocationTlv {
    fn tlv_name(&self) -> String {
        "Location".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        LocationTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
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
                let mut sub_tlvs: Tlvs = TryFrom::<&[u8]>::try_from(&tlv.value[start_offset..])?;

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
}

pub struct LocationTlvReflectorConfig {}

impl TlvHandlerGenerator for LocationTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "location".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandler + Send> {
        Box::new(LocationTlv {})
    }
}

#[cfg(test)]
mod location_tlv_tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::{
        handlers::TlvReflectorHandler,
        netconf,
        parameters::TestArguments,
        server::SessionData,
        test::stamp_handler_test_support::create_test_logger,
        tlv::{Error, Tlv},
        tlvs::location::LocationTlv,
    };

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
        let tlv =
            TryInto::<Tlv>::try_into(outter_raw_data.as_slice()).expect("Outter TLV should parse");

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

        assert!(matches!(reparsed_sub_tlv, Error::NotEnoughData));
        assert!(handled.value[4] & 0x40 != 0);
    }
}
