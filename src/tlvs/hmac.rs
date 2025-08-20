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

use std::net::{SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};
use std::sync::{Arc, Mutex};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::{NetConfiguration, NetConfigurationItem},
    parameters::TestArguments,
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Error, Flags, Tlv},
};

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

impl TlvReflectorHandler for HmacTlv {
    fn tlv_name(&self) -> String {
        "HMAC TLV".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::HMAC_TLV].to_vec()
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
}

impl TlvHandler for HmacTlv {
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

impl TlvSenderHandler for HmacTlv {
    fn tlv_name(&self) -> String {
        "HMAC TLV".into()
    }

    fn tlv_sender_command(&self, command: Command) -> Command {
        HmacTlvCommand::augment_subcommands(command)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::HMAC_TLV].to_vec()
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
}

pub struct HmacTlvReflectorConfig {}

impl TlvHandlerGenerator for HmacTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "hmac".into()
    }

    fn generate(&self) -> Arc<Mutex<dyn TlvReflectorHandler + Send>> {
        Arc::new(Mutex::new(HmacTlv::default()))
    }

    fn configure(&self) {
        println!("Going to configure a reflected-control\n");
    }
}

#[cfg(test)]
mod hmac_tlv_tests {
    use crate::{
        stamp::StampError,
        tlv::{self, Flags, Tlv},
        tlvs::hmac::HmacTlv,
    };

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
