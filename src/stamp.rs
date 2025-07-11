/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2024, 2025 Will Hawkins and Cerfcast
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

use serde::Serialize;

use crate::handlers::HandlerError;
use crate::ntp::{self, ErrorEstimate, NtpError, NtpTime};
use crate::parameters::TestArgumentKind;
use crate::tlv::{self, Tlvs};
use crate::util;

use std::fmt::{Debug, Display};
use std::str::FromStr;

pub const MBZ_VALUE: u8 = 0x00;

#[derive(Clone)]
pub enum StampParseAttemptType {
    MessageBody,
    Basic,
    Mbz,
    Sender,
    SenderUnauthenticated,
    SenderAuthenticated,
    Response,
    ResponseUnauthenticated,
    ResponseAuthenticated,
}

impl Debug for StampParseAttemptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StampParseAttemptType::MessageBody => write!(f, "STAMP message body"),
            StampParseAttemptType::Basic => write!(f, "STAMP basic message fields"),
            StampParseAttemptType::Mbz => write!(f, "STAMP Must-be-zero bytes"),
            StampParseAttemptType::Sender => write!(f, "STAMP sender message body"),
            StampParseAttemptType::SenderAuthenticated => {
                write!(f, "STAMP authenticated sender message body")
            }
            StampParseAttemptType::SenderUnauthenticated => {
                write!(f, "STAMP unauthenticated sender message body")
            }
            StampParseAttemptType::Response => write!(f, "STAMP response message body"),
            StampParseAttemptType::ResponseAuthenticated => {
                write!(f, "STAMP authenticated response message body")
            }
            StampParseAttemptType::ResponseUnauthenticated => {
                write!(f, "STAMP unauthenticated response message body")
            }
        }
    }
}

pub enum StampError {
    Other(String),
    MissingRequiredArgument(TestArgumentKind),
    HandlerError(HandlerError),
    Ntp(NtpError),
    Io(std::io::Error),
    MalformedTlv(tlv::Error),
    InvalidSignature,
    Malformed(StampParseAttemptType, String),
    SignalHandlerFailure(String),
}

impl From<std::io::Error> for StampError {
    fn from(value: std::io::Error) -> Self {
        StampError::Io(value)
    }
}

// Note: Although it may be useful, there is no From between
// NtpError and StampError because an NtpError can occur in
// different contexts.

impl Display for StampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StampError::Other(s) => write!(f, "Other Stamp error: {s}"),
            StampError::Io(e) => write!(f, "IO error: {e}"),
            StampError::Ntp(e) => write!(f, "NTP error: {e}"),
            StampError::MissingRequiredArgument(arg) => {
                write!(f, "An argument for a test was missing: {arg:?}")
            }
            StampError::MalformedTlv(e) => write!(f, "Malformed TLV error: {e:?}"),
            StampError::InvalidSignature => write!(f, "Stamp message had an invalid signature"),
            StampError::Malformed(tpe, message) => {
                write!(f, "Error parsing {tpe:?}: {message}")
            }
            StampError::SignalHandlerFailure(message) => {
                write!(f, "Error occurred setting the signal handler: {message}")
            }
            StampError::HandlerError(s) => write!(f, "Handler error: {s:?}"),
        }
    }
}

impl Debug for StampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Hash, Eq)]
pub struct Mbz<const L: usize, const V: u8> {}

impl<const L: usize, const V: u8> TryFrom<&[u8]> for Mbz<L, V> {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if !value.iter().take(L).all(|b| *b == V) {
            return Err(StampError::Malformed(
                StampParseAttemptType::Mbz,
                format!("MBZ bytes were not all {V}").to_string(),
            ));
        }
        if value.len() < L {
            return Err(StampError::Malformed(
                StampParseAttemptType::Mbz,
                format!(
                    "MBZ bytes were not the proper size ({} vs {})",
                    L,
                    value.len()
                )
                .to_string(),
            ));
        }
        Ok(Self {})
    }
}

impl<const L: usize, const V: u8> From<&Mbz<L, V>> for Vec<u8> {
    fn from(_: &Mbz<L, V>) -> Self {
        vec![V; L]
    }
}

impl<const L: usize, const V: u8> From<&Mbz<L, V>> for [u8; L] {
    fn from(_: &Mbz<L, V>) -> Self {
        [V; L]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StampSendBodyType {
    UnAuthenticated(Mbz<28, MBZ_VALUE>),
    Authenticated(Mbz<68, MBZ_VALUE>),
}

impl TryFrom<&[u8]> for StampSendBodyType {
    type Error = StampError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let error_msg = match TryInto::<Mbz<68, MBZ_VALUE>>::try_into(value) {
            Ok(body) => return Ok(StampSendBodyType::Authenticated(body)),
            Err(e) => Some(format!("Authenticated send body parsing failed: {e:?}")),
        };

        let error_msg = match TryInto::<Mbz<28, MBZ_VALUE>>::try_into(value) {
            Ok(body) => return Ok(StampSendBodyType::UnAuthenticated(body)),
            Err(e) => {
                let this_err = Some(format!("Unauthenticated send body parsing failed: {e:?}"));
                [error_msg, this_err]
                    .iter()
                    .flatten()
                    .fold("".to_string(), |acc, n| {
                        let base = if !acc.is_empty() {
                            acc + "; "
                        } else {
                            "".into()
                        };
                        base + n
                    })
            }
        };

        Err(StampError::Malformed(StampParseAttemptType::Sender,
            format!("Could not parse the bytes of the message's body into a stamp send body -- the following errors occurred while trying to parse the bytes into a send body: {error_msg}")
        ))
    }
}

impl From<&StampSendBodyType> for Vec<u8> {
    fn from(value: &StampSendBodyType) -> Vec<u8> {
        match value {
            StampSendBodyType::Authenticated(mbz) => Into::<Vec<u8>>::into(mbz),
            StampSendBodyType::UnAuthenticated(mbz) => Into::<Vec<u8>>::into(mbz),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StampResponseBodyType {
    Authenticated(StampResponseBody),
    UnAuthenticated(StampResponseBody),
}

#[derive(Clone, Default, PartialEq)]
pub struct StampResponseBody {
    pub received_time: ntp::NtpTime,
    pub sent_sequence: u32,
    pub sent_time: ntp::NtpTime,
    pub sent_error: ntp::ErrorEstimate,
    pub received_ttl: u8,
}

impl Debug for StampResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StampResponseBody")
            .field("received_time", &self.received_time)
            .field(
                "sent_sequence",
                &format_args!("0x{:x?}", self.sent_sequence),
            )
            .field("sent_time", &self.sent_time)
            .field("sent_error", &self.sent_error)
            .field("received_ttl", &format_args!("0x{:x?}", self.received_ttl))
            .finish()
    }
}

impl StampResponseBodyType {
    fn try_from_authenticated_raw(value: &[u8]) -> Result<StampResponseBody, StampError> {
        let mut raw_index = 0;

        // Received timestamp
        StampMsg::too_short(
            raw_index + 4,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<4, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 4])?;
        raw_index += 4;

        // Received timestamp
        StampMsg::too_short(
            raw_index + NtpTime::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let received_time = ntp::NtpTime::try_from(&value[raw_index..raw_index + NtpTime::RawSize])
            .map_err(|e| {
                StampError::Malformed(StampParseAttemptType::ResponseAuthenticated, e.to_string())
            })?;
        raw_index += NtpTime::RawSize;

        // 8 MBZ
        StampMsg::too_short(
            raw_index + 8,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<8, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 8])?;
        raw_index += 8;

        // Sent sequence #
        StampMsg::too_short(
            raw_index + 4,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_sequence = u32::from_be_bytes(value[raw_index..raw_index + 4].try_into().unwrap());
        raw_index += 4;

        // 12 MBZ
        StampMsg::too_short(
            raw_index + 12,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<12, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 12])?;
        raw_index += 12;

        // Sent Timestamp
        StampMsg::too_short(
            raw_index + NtpTime::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_time = ntp::NtpTime::try_from(&value[raw_index..raw_index + NtpTime::RawSize])
            .map_err(|e| {
                StampError::Malformed(StampParseAttemptType::ResponseAuthenticated, e.to_string())
            })?;
        raw_index += NtpTime::RawSize;

        // Sent Error Estimate
        StampMsg::too_short(
            raw_index + ErrorEstimate::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_error =
            ntp::ErrorEstimate::try_from(&value[raw_index..raw_index + ErrorEstimate::RawSize])
                .map_err(|e| {
                    StampError::Malformed(
                        StampParseAttemptType::ResponseAuthenticated,
                        format!("{e:?}"),
                    )
                })?;
        raw_index += ErrorEstimate::RawSize;

        // 6 MBZ
        StampMsg::too_short(
            raw_index + 6,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<6, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 6])?;
        raw_index += 6;

        // Received TTL
        StampMsg::too_short(
            raw_index,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let received_ttl = value[raw_index];
        raw_index += 1;

        // 15 MBZ
        StampMsg::too_short(
            raw_index + 15,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseAuthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<15, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 15])?;

        Ok(StampResponseBody {
            received_time,
            sent_sequence,
            sent_time,
            sent_error,
            received_ttl,
        })
    }

    fn try_from_unauthenticated_raw(value: &[u8]) -> Result<StampResponseBody, StampError> {
        let mut raw_index = 0;

        StampMsg::too_short(
            raw_index + NtpTime::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let received_time = ntp::NtpTime::try_from(&value[raw_index..raw_index + NtpTime::RawSize])
            .map_err(|e| {
                StampError::Malformed(
                    StampParseAttemptType::ResponseUnauthenticated,
                    e.to_string(),
                )
            })?;
        raw_index += NtpTime::RawSize;

        StampMsg::too_short(
            raw_index + 4,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_sequence = u32::from_be_bytes(value[raw_index..raw_index + 4].try_into().unwrap());
        raw_index += 4;

        StampMsg::too_short(
            raw_index + NtpTime::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_time = ntp::NtpTime::try_from(&value[raw_index..raw_index + NtpTime::RawSize])
            .map_err(|e| {
                StampError::Malformed(
                    StampParseAttemptType::ResponseUnauthenticated,
                    e.to_string(),
                )
            })?;
        raw_index += NtpTime::RawSize;

        StampMsg::too_short(
            raw_index + ErrorEstimate::RawSize,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let sent_error =
            ntp::ErrorEstimate::try_from(&value[raw_index..raw_index + ErrorEstimate::RawSize])
                .map_err(|e| match e {
                    NtpError::InvalidData(e) => {
                        StampError::Malformed(StampParseAttemptType::ResponseUnauthenticated, e)
                    }
                })?;
        raw_index += ErrorEstimate::RawSize;

        StampMsg::too_short(
            raw_index + 2,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<2, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 2])?;
        raw_index += 2;

        StampMsg::too_short(
            raw_index,
            value.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let received_ttl = value[raw_index];
        raw_index += 1;

        StampMsg::too_short(
            raw_index + 3,
            value.len(),
            StampError::Malformed(
                StampParseAttemptType::ResponseUnauthenticated,
                "Packet is too short".to_string(),
            ),
        )?;
        let _ = Mbz::<3, MBZ_VALUE>::try_from(&value[raw_index..raw_index + 3])?;

        Ok(StampResponseBody {
            received_time,
            sent_sequence,
            sent_time,
            sent_error,
            received_ttl,
        })
    }
}

impl TryFrom<&[u8]> for StampResponseBodyType {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let err_msg = match StampResponseBodyType::try_from_authenticated_raw(value) {
            Ok(body) => return Ok(StampResponseBodyType::Authenticated(body)),
            Err(e) => Some(format!("Authenticated response body parsing failed: {e:?}")),
        };

        let error_msg = match StampResponseBodyType::try_from_unauthenticated_raw(value) {
            Ok(body) => return Ok(StampResponseBodyType::UnAuthenticated(body)),
            Err(e) => {
                let this_err = Some(format!(
                    "Unauthenticated response body parsing failed: {e:?}"
                ));
                [err_msg, this_err]
                    .iter()
                    .flatten()
                    .fold("".to_string(), |acc, n| {
                        let base = if !acc.is_empty() {
                            acc + "; "
                        } else {
                            "".into()
                        };
                        base + n
                    })
            }
        };

        Err(StampError::Malformed(
            StampParseAttemptType::Response,
                format!("Could not parse the bytes of the message's body into a stamp response body -- the following errors occurred while trying to parse the bytes into a send body: {error_msg}")
        ))
    }
}

impl From<&StampResponseBodyType> for Vec<u8> {
    fn from(value: &StampResponseBodyType) -> Self {
        match value {
            StampResponseBodyType::UnAuthenticated(body) => {
                let mut result = vec![];
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.received_time));
                result.extend_from_slice(&body.sent_sequence.to_be_bytes());
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.sent_time));
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.sent_error));
                result.extend_from_slice(&[MBZ_VALUE; 2]);
                result.extend_from_slice(&[body.received_ttl]);
                result.extend_from_slice(&[MBZ_VALUE; 3]);
                result
            }
            StampResponseBodyType::Authenticated(body) => {
                let mut result = vec![];
                result.extend_from_slice(&[MBZ_VALUE; 4]);
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.received_time));
                result.extend_from_slice(&[MBZ_VALUE; 8]);
                result.extend_from_slice(&body.sent_sequence.to_be_bytes());
                result.extend_from_slice(&[MBZ_VALUE; 12]);
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.sent_time));
                result.extend_from_slice(&Into::<Vec<u8>>::into(&body.sent_error));
                result.extend_from_slice(&[MBZ_VALUE; 6]);
                result.extend_from_slice(&[body.received_ttl]);
                result.extend_from_slice(&[MBZ_VALUE; 15]);
                result
            }
        }
    }
}

#[derive(PartialEq, Clone)]
pub struct RawStampHmac {
    hmac: Vec<u8>,
}

impl Debug for RawStampHmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HMAC (in hex): {:x?}", self.hmac)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StampMsgBody {
    Response(StampResponseBodyType),
    Send(StampSendBodyType),
}

impl StampMsgBody {
    #[allow(non_upper_case_globals)]
    pub const RawSize: usize = 28;

    pub fn len(&self) -> usize {
        match self {
            Self::Response(StampResponseBodyType::Authenticated(_)) => 68,
            Self::Response(StampResponseBodyType::UnAuthenticated(_)) => 28,
            Self::Send(StampSendBodyType::Authenticated(_)) => 68,
            Self::Send(StampSendBodyType::UnAuthenticated(_)) => 28,
        }
    }
}

impl Default for StampMsgBody {
    fn default() -> Self {
        StampMsgBody::Send(StampSendBodyType::UnAuthenticated(Default::default()))
    }
}

impl TryFrom<&[u8]> for StampMsgBody {
    type Error = StampError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let error_msg = match TryInto::<StampSendBodyType>::try_into(value) {
            Ok(body) => {
                return Ok(Self::Send(body));
            }
            Err(e) => Some(format!("Could not parse into a send body: {e:?}")),
        };

        let error_msg = match TryInto::<StampResponseBodyType>::try_into(value) {
            Ok(body) => {
                return Ok(Self::Response(body));
            }
            Err(e) => {
                let this_err = Some(format!("Could not parse into a response body: {e:?}"));
                [error_msg, this_err]
                    .iter()
                    .flatten()
                    .fold("".to_string(), |acc, n| {
                        let base = if !acc.is_empty() {
                            acc + "; "
                        } else {
                            "".into()
                        };
                        base + n
                    })
            }
        };

        Err(StampError::Malformed(StampParseAttemptType::MessageBody,
            format!("Could not parse the bytes of the message's body into a STAMP send or response body: {error_msg}")
        ))
    }
}

impl From<StampMsgBody> for Vec<u8> {
    fn from(value: StampMsgBody) -> Vec<u8> {
        match value {
            StampMsgBody::Response(response) => (&response).into(),
            StampMsgBody::Send(send) => (&send).into(),
        }
    }
}

#[derive(Serialize, Clone, PartialEq, Eq, Hash)]
pub enum Ssid {
    Mbz(Mbz<2, MBZ_VALUE>),
    Ssid(u16),
}

impl Ssid {
    #[allow(non_upper_case_globals)]
    pub const RawSize: usize = 2;
}

impl Default for Ssid {
    fn default() -> Self {
        Self::Mbz(Mbz::<2, MBZ_VALUE> {})
    }
}

impl FromStr for Ssid {
    type Err = clap::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First, determine if the user put `0x` in front. If so, drop that!
        Ok(Self::Ssid(match s.strip_prefix("0x") {
            Some(ret) => u16::from_str_radix(ret, 16)
                .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?,
            _ => s
                .parse()
                .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?,
        }))
    }
}

impl From<Ssid> for Vec<u8> {
    fn from(value: Ssid) -> Self {
        let mut result = [0u8, 0u8];
        if let Ssid::Ssid(ssid) = value {
            result.copy_from_slice(&ssid.to_be_bytes());
        }
        result.to_vec()
    }
}

impl TryFrom<&[u8]> for Ssid {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value[0] == 0 && value[1] == 0 {
            Ok(Ssid::Mbz(Default::default()))
        } else {
            Ok(Ssid::Ssid(u16::from_be_bytes(value.try_into().unwrap())))
        }
    }
}

impl Debug for Ssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ssid::Mbz(_) => write!(f, "MBZ"),
            Ssid::Ssid(s) => write!(f, "0x{s:02x}"),
        }
    }
}

#[cfg(test)]
mod ssid_test {
    use crate::stamp::Ssid;
    #[test]
    fn test_parse_hex_ssid_with_0x() {
        let res: Ssid = "0xabcd"
            .parse()
            .expect("Could not parse 0xabcd into an Ssid");
        assert!(matches!(res, Ssid::Ssid(0xabcd)))
    }

    #[test]
    fn test_parse_hex_ssid_without_0x() {
        let res: Result<Ssid, clap::Error> = "abcd".parse();
        assert!(res.is_err())
    }

    #[test]
    fn test_parse_dec_ssid_without_0x() {
        let res: Ssid = "52719".parse().expect("Could not parse 52719 into an Ssid");
        assert!(matches!(res, Ssid::Ssid(52719)))
    }

    #[test]
    fn test_parse_dec_ssid_with_0x() {
        let res: Ssid = "0x5279"
            .parse()
            .expect("Could not parse 0x5279 into an Ssid");
        assert!(matches!(res, Ssid::Ssid(0x5279)))
    }

    #[test]
    fn test_parse_ssid_with_only_0x() {
        let res: Result<Ssid, clap::Error> = "0x".parse();
        assert!(res.is_err())
    }

    #[test]
    fn test_parse_ssid_convert_to_bytes() {
        let res: Ssid = "0xabcd"
            .parse()
            .expect("Could not parse 0xabcd into an Ssid");
        let bytes: Vec<_> = res.into();
        assert_eq!(bytes, vec![0xab, 0xcd])
    }

    #[test]
    fn test_parse_ssid_convert_to_bytes_dec() {
        let res: Ssid = "5250".parse().expect("Could not parse 5250 into an Ssid");
        let bytes: Vec<_> = res.into();
        assert_eq!(bytes, vec![0x14, 0x82])
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StampMsg {
    pub sequence: u32,
    pub time: ntp::NtpTime,
    pub error: ntp::ErrorEstimate,
    pub ssid: Ssid,
    pub body: StampMsgBody,
    pub hmac: Option<RawStampHmac>,
    pub tlvs: Tlvs,
    pub raw_length: Option<usize>,
}

const DEFAULT_KEY: &[u8] = &[0x00];

impl StampMsg {
    pub fn authenticate(&self, key: &Option<Vec<u8>>) -> Result<Option<RawStampHmac>, StampError> {
        match &self.body {
            StampMsgBody::Response(StampResponseBodyType::Authenticated(_))
            | StampMsgBody::Send(StampSendBodyType::Authenticated(_)) => {
                let body_bytes: Vec<u8> = self.base_into_bytes();
                let result =
                    util::authenticate(&body_bytes, key.as_ref().unwrap_or(&DEFAULT_KEY.to_vec()))?;
                Ok(Some(RawStampHmac { hmac: result }))
            }
            _ => Ok(None),
        }
    }

    fn base_into_bytes(&self) -> Vec<u8> {
        let mut result = vec![0u8; 0];
        result.extend(&self.sequence.to_be_bytes());

        match self.body {
            StampMsgBody::Response(StampResponseBodyType::Authenticated(_))
            | StampMsgBody::Send(StampSendBodyType::Authenticated(_)) => {
                result.extend(&Into::<Vec<u8>>::into(&Mbz::<12, MBZ_VALUE> {}));
            }
            _ => {}
        };

        result.extend(&Into::<Vec<u8>>::into(&self.time));
        result.extend(&Into::<Vec<u8>>::into(&self.error));
        result.extend(&Into::<Vec<u8>>::into(self.ssid.clone()));
        result.extend(&Into::<Vec<u8>>::into(self.body.clone()));

        result
    }
}

impl From<StampMsg> for Vec<u8> {
    fn from(value: StampMsg) -> Self {
        let mut result = value.base_into_bytes();

        // If there is an HMAC, add it now.
        if let Some(hmac) = value.hmac {
            result.extend_from_slice(&hmac.hmac);
        }

        result.extend_from_slice(&Into::<Vec<u8>>::into(value.tlvs));

        result
    }
}

impl StampMsg {
    fn too_short<T>(destination: usize, len: usize, err: T) -> Result<(), T> {
        if destination > len {
            Err(err)
        } else {
            Ok(())
        }
    }
}

impl TryFrom<&[u8]> for StampMsg {
    type Error = StampError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let mut raw_idx: usize = 0;

        StampMsg::too_short(
            raw_idx + 4,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let sequence = u32::from_be_bytes(
            raw[0..4]
                .try_into()
                .map_err(|_| StampError::Other("Invalid sequence number.".to_string()))?,
        );
        raw_idx += 4;

        StampMsg::too_short(
            raw_idx,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let authenticated_pkt = if TryInto::<Mbz<12, 0>>::try_into(&raw[raw_idx..]).is_ok() {
            raw_idx += 12;
            true
        } else {
            false
        };

        StampMsg::too_short(
            raw_idx + NtpTime::RawSize,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let time: NtpTime = raw[raw_idx..raw_idx + NtpTime::RawSize]
            .try_into()
            .map_err(|e: NtpError| {
                StampError::Malformed(StampParseAttemptType::ResponseAuthenticated, e.to_string())
            })?;
        raw_idx += NtpTime::RawSize;

        StampMsg::too_short(
            raw_idx + ErrorEstimate::RawSize,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let ee: ErrorEstimate = raw[raw_idx..raw_idx + ErrorEstimate::RawSize]
            .try_into()
            .map_err(|e: NtpError| match e {
                NtpError::InvalidData(e) => {
                    StampError::Malformed(StampParseAttemptType::ResponseUnauthenticated, e)
                }
            })?;

        raw_idx += ErrorEstimate::RawSize;

        StampMsg::too_short(
            raw_idx + Ssid::RawSize,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let ssid: Ssid = raw[raw_idx..raw_idx + Ssid::RawSize].try_into()?;
        raw_idx += Ssid::RawSize;

        StampMsg::too_short(
            raw_idx,
            raw.len(),
            StampError::Other("Packet is too short".to_string()),
        )?;
        let body = TryInto::<StampMsgBody>::try_into(&raw[raw_idx..])?;
        raw_idx += body.len();

        let hmac = if authenticated_pkt {
            StampMsg::too_short(
                raw_idx + 16,
                raw.len(),
                StampError::Other("Packet is too short".to_string()),
            )?;
            // TODO: Read the hmac!
            let hmac = Some(RawStampHmac {
                hmac: raw[raw_idx..raw_idx + 16].to_vec(),
            });
            raw_idx += 16;
            hmac
        } else {
            None
        };

        let mut tlvs: Tlvs = raw[raw_idx..].try_into()?;

        // Even though the TLVs parsed, there could still be malformation (e.g.,
        // an HMAC TLV in the wrong spot).
        tlvs.handle_malformed_response();

        Ok(StampMsg {
            sequence,
            time,
            error: ee,
            ssid,
            body,
            hmac,
            tlvs,
            raw_length: Some(raw.len()),
        })
    }
}

#[cfg(test)]
mod stamp_test_messages {

    use super::*;

    pub const UNAUTHENTICATED_STAMP_PKT_SIZE: usize = 44; // in octets
    pub const AUTHENTICATED_STAMP_PKT_SIZE: usize = 112; // in octets

    pub const COMMON_EXPECTED_SEQUENCE: u32 = 5;
    pub const COMMON_EXPECTED_SECONDS: u32 = 6;
    pub const COMMON_EXPECTED_FRACTIONS: u32 = 7;
    pub const COMMON_EXPECTED_SENT_SECONDS: u32 = 8;
    pub const COMMON_EXPECTED_SENT_FRACTIONS: u32 = 9;
    pub const COMMON_EXPECTED_SCALE: u8 = 0;
    pub const COMMON_EXPECTED_MULTIPLE: u8 = 2;
    pub const COMMON_EXPECTED_SSID: u16 = 254;
    pub const COMMON_EXPECTED_HMAC: &[u8] = &[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    pub const COMMON_EXPECTED_TTL: u8 = 0x17;

    pub fn simple_stamp_message_from_bytes(authenticated: bool) -> Vec<u8> {
        let mut raw_data = if authenticated {
            [0; AUTHENTICATED_STAMP_PKT_SIZE].to_vec()
        } else {
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE].to_vec()
        };

        let mut index = 0;
        raw_data[index..index + 4].copy_from_slice(&u32::to_be_bytes(COMMON_EXPECTED_SEQUENCE));
        index += 4;

        if authenticated {
            index += 12;
        }

        raw_data[index..index + 4].copy_from_slice(&u32::to_be_bytes(COMMON_EXPECTED_SECONDS));
        index += 4;
        raw_data[index..index + 4].copy_from_slice(&u32::to_be_bytes(COMMON_EXPECTED_FRACTIONS));
        index += 4;

        raw_data[index] = 0x80;
        index += 1;
        raw_data[index] = 0x02;
        index += 1;
        raw_data[index..index + 2].copy_from_slice(&u16::to_be_bytes(COMMON_EXPECTED_SSID));
        index += 2;

        if authenticated {
            raw_data[index..index + 68].copy_from_slice([MBZ_VALUE; 68].as_slice());
            index += 68;
            raw_data[index..index + 16].copy_from_slice(COMMON_EXPECTED_HMAC);
        } else {
            raw_data[index..index + 28].copy_from_slice([MBZ_VALUE; 28].as_slice());
        }
        raw_data
    }

    fn simple_stamp_from_bytes_test(authenticated: bool) {
        let raw_data = simple_stamp_message_from_bytes(authenticated);
        let stamp_pkt: Result<StampMsg, StampError> = raw_data.as_slice().try_into();

        if stamp_pkt.is_err() {
            panic!(
                "There was an error parsing the test message: {:?}",
                stamp_pkt.unwrap_err()
            )
        }
        let stamp_pkt = stamp_pkt.unwrap();

        if stamp_pkt.time.seconds != COMMON_EXPECTED_SECONDS {
            panic!(
                "Incorrect seconds. Got {}, wanted {}.",
                stamp_pkt.time.seconds, COMMON_EXPECTED_SECONDS
            );
        }
        if stamp_pkt.time.fractions != COMMON_EXPECTED_FRACTIONS {
            panic!(
                "Incorrect fractions. Got {}, wanted {}.",
                stamp_pkt.time.fractions, COMMON_EXPECTED_FRACTIONS
            );
        }
        if stamp_pkt.sequence != COMMON_EXPECTED_SEQUENCE {
            panic!(
                "Incorrect sequence. Got {}, wanted {}.",
                stamp_pkt.sequence, COMMON_EXPECTED_SEQUENCE
            );
        }

        if stamp_pkt.error.scale != COMMON_EXPECTED_SCALE {
            panic!(
                "Incorrect error scale. Got {}, wanted {}.",
                stamp_pkt.error.scale, COMMON_EXPECTED_SCALE
            );
        }

        if stamp_pkt.error.multiple != COMMON_EXPECTED_MULTIPLE {
            panic!(
                "Incorrect error multiple. Got {}, wanted {}.",
                stamp_pkt.error.multiple, COMMON_EXPECTED_MULTIPLE
            );
        }

        if !stamp_pkt.error.synchronized {
            panic!("Incorrect error synchronized status. Got false, wanted true.");
        }

        match &stamp_pkt.ssid {
            Ssid::Mbz(_) => panic!("Incorrect error synchronized status. Got false, wanted true."),
            Ssid::Ssid(ssid) => {
                if *ssid != COMMON_EXPECTED_SSID {
                    panic!("Incorrect ssid. Wanted {COMMON_EXPECTED_SSID}, got {ssid}");
                }
            }
        }

        match &stamp_pkt.body {
            StampMsgBody::Send(StampSendBodyType::Authenticated(_)) => {
                assert!(authenticated);
            }
            StampMsgBody::Send(StampSendBodyType::UnAuthenticated(_)) => {
                assert!(!authenticated);
            }
            StampMsgBody::Response(StampResponseBodyType::Authenticated(_)) => {
                assert!(authenticated);
            }
            StampMsgBody::Response(StampResponseBodyType::UnAuthenticated(_)) => {
                assert!(!authenticated);
            }
        }

        if authenticated {
            assert!(stamp_pkt.hmac.is_some());
        }
    }

    #[test]
    fn simple_stamp_from_bytes_unauthenticated_test() {
        simple_stamp_from_bytes_test(false);
    }
    #[test]
    fn simple_stamp_from_bytes_authenticated_test() {
        simple_stamp_from_bytes_test(true);
    }
}

#[cfg(test)]
mod stamp_test_messages_bad {
    use super::*;
    #[test]
    fn simple_stamp_from_bytes_unauthenticated_test() {
        let mut raw_data = super::stamp_test_messages::simple_stamp_message_from_bytes(false);

        raw_data = raw_data[0..27].to_vec();
        let stamp_pkt: Result<StampMsg, StampError> = raw_data.as_slice().try_into();

        assert!(stamp_pkt.is_err());
    }
}

#[cfg(test)]
mod stamp_test_messages_with_tlvs {
    use stamp_test_messages::UNAUTHENTICATED_STAMP_PKT_SIZE;

    use super::*;

    #[test]
    fn simple_stamp_malformed_tlv_test_data_too_short() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8)];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x01;
        raw_data[14..16].copy_from_slice(&0u16.to_be_bytes());
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x20;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 1] = 0xfe;
        // TLV Length: There are only 8 bytes in the "value" of the Tlv, but we say that there are 9.
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 2..UNAUTHENTICATED_STAMP_PKT_SIZE + 4]
            .copy_from_slice(&u16::to_be_bytes(9));
        // TLV Data
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 4..UNAUTHENTICATED_STAMP_PKT_SIZE + 12]
            .copy_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!((stamp_pkt.tlvs.malformed.is_some()));

        let malformed = stamp_pkt.tlvs.malformed.unwrap();

        assert!(malformed.bytes.len() == (1 + 1 + 2 + 8));
    }

    #[test]
    fn simple_stamp_malformed_tlv_test_tlv_flag_only() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1)];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x01;
        raw_data[14..16].copy_from_slice(&0u16.to_be_bytes());
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x20;

        let stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!((stamp_pkt.tlvs.malformed.is_some()));

        let malformed = stamp_pkt.tlvs.malformed.unwrap();

        assert!(malformed.bytes.len() == 1);
    }

    #[test]
    fn simple_stamp_malformed_tlv_test_tlv_flag_type_only() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1)];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x01;
        raw_data[14..16].copy_from_slice(&0u16.to_be_bytes());
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x20;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 1] = 0xfe;

        let stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!((stamp_pkt.tlvs.malformed.is_some()));

        let malformed = stamp_pkt.tlvs.malformed.unwrap();

        assert!(malformed.bytes.len() == 2);
    }

    #[test]
    fn simple_stamp_malformed_tlv_test_flag_type_partial_length() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 1)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 1)];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x01;
        raw_data[14..16].copy_from_slice(&0u16.to_be_bytes());
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x20;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 1] = 0xfe;
        // TLV Length: There are only 8 bytes in the "value" of the Tlv, but we say that there are 9.
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 2..UNAUTHENTICATED_STAMP_PKT_SIZE + 3]
            .copy_from_slice([0xde; 1].as_slice());

        let stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!((stamp_pkt.tlvs.malformed.is_some()));

        let malformed = stamp_pkt.tlvs.malformed.unwrap();

        assert!(malformed.bytes.len() == (1 + 1 + 1));
    }

    #[test]
    fn simple_stamp_from_bytes_one_tlv_test() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8)];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x01;
        raw_data[14..16].copy_from_slice(&0u16.to_be_bytes());
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x20;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 1] = 0xfe;
        // TLV Length
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 2..UNAUTHENTICATED_STAMP_PKT_SIZE + 4]
            .copy_from_slice(&u16::to_be_bytes(8));
        // TLV Data
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 4..UNAUTHENTICATED_STAMP_PKT_SIZE + 12]
            .copy_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let stamp_pkt: Result<StampMsg, StampError> = raw_data.as_slice().try_into();

        if stamp_pkt.is_err() {
            panic!(
                "There was an error parsing the test message: {:?}",
                stamp_pkt.unwrap_err()
            )
        }
        let stamp_pkt = stamp_pkt.unwrap();

        if stamp_pkt.time.seconds != expected_seconds {
            panic!(
                "Incorrect seconds. Got {}, wanted {}.",
                stamp_pkt.time.seconds, expected_seconds
            );
        }
        if stamp_pkt.time.fractions != expected_fracs {
            panic!(
                "Incorrect fractions. Got {}, wanted {}.",
                stamp_pkt.time.fractions, expected_fracs
            );
        }
        if stamp_pkt.sequence != expected_sequence {
            panic!(
                "Incorrect sequence. Got {}, wanted {}.",
                stamp_pkt.sequence, expected_sequence
            );
        }

        if let Ssid::Ssid(_) = stamp_pkt.ssid {
            panic!("Should have gotten mbz in ssid!");
        }

        if stamp_pkt.tlvs.tlvs.len() != 1 {
            panic!("Got {} tlvs, expected 1", stamp_pkt.tlvs.tlvs.len());
        }

        let parsed_tlv = stamp_pkt.tlvs.tlvs[0].clone();
        if parsed_tlv.flags.get_raw() != 0x20 {
            panic!("Got {:?} flags, expected 0x20", parsed_tlv.flags);
        }
        if parsed_tlv.tpe != 0xfe {
            panic!("Got {} type, expected 0xfe", parsed_tlv.tpe);
        }
        if parsed_tlv.length != 0x8 {
            panic!("Got {} length, expected 0x8", parsed_tlv.length);
        }

        let contents = u64::from_be_bytes(parsed_tlv.value.clone().try_into().unwrap());
        if contents != 0x1122334455667788 {
            panic!("Got {contents} contents, expected 0x1122334455667788");
        }

        let tlv_bytes: Vec<u8> = parsed_tlv.into();

        if !raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE..UNAUTHENTICATED_STAMP_PKT_SIZE + 12]
            .eq(tlv_bytes.as_slice())
        {
            panic!("Serialized TLV bytes did not match expected bytes.")
        }
    }

    #[test]
    fn test_extra_padding_stamp() {
        let mut tlvs_bytes = [0u8; 16];
        tlvs_bytes[0] = 0x0;
        tlvs_bytes[1] = 0x1;
        tlvs_bytes[2..4].copy_from_slice(&12u16.to_be_bytes());

        let tlvs = Tlvs {
            tlvs: [tlv::Tlv::extra_padding(12)].to_vec(),
            malformed: None,
        };
        let msg = StampMsg {
            time: NtpTime {
                seconds: 0x5,
                fractions: 0x6,
            },
            sequence: 0x11,
            error: Default::default(),
            ssid: Default::default(),
            body: Default::default(),
            hmac: None,
            tlvs,
            raw_length: None,
        };

        let serialized_msg = Into::<Vec<u8>>::into(msg);

        if serialized_msg.len() != 44 + 16 {
            panic!("Serialized message size was incorrect!")
        }

        if !serialized_msg[44..44 + 16].eq(tlvs_bytes.as_slice()) {
            panic!("Serialized extra padding TLV bytes were not correct.");
        }
    }
}

#[cfg(test)]
mod stamp_response_test {

    use stamp_test_messages::{
        COMMON_EXPECTED_FRACTIONS, COMMON_EXPECTED_SECONDS, COMMON_EXPECTED_SENT_FRACTIONS,
        COMMON_EXPECTED_SENT_SECONDS, COMMON_EXPECTED_SEQUENCE, COMMON_EXPECTED_TTL,
    };

    use super::*;

    fn do_simple_stamp_response_deserialize(authenticated: bool) {
        let body = StampResponseBody {
            received_time: ntp::NtpTime {
                seconds: COMMON_EXPECTED_SECONDS,
                fractions: COMMON_EXPECTED_FRACTIONS,
            },
            sent_sequence: COMMON_EXPECTED_SEQUENCE,
            sent_time: ntp::NtpTime {
                seconds: COMMON_EXPECTED_SENT_SECONDS,
                fractions: COMMON_EXPECTED_SENT_FRACTIONS,
            },
            sent_error: Default::default(),
            received_ttl: COMMON_EXPECTED_TTL,
        };

        let expected = if authenticated {
            StampResponseBodyType::Authenticated(body)
        } else {
            StampResponseBodyType::UnAuthenticated(body)
        };
        let mut raw = vec![];

        if authenticated {
            raw.extend_from_slice([MBZ_VALUE; 4].as_slice());
        }
        raw.extend_from_slice(&COMMON_EXPECTED_SECONDS.to_be_bytes());
        raw.extend_from_slice(&COMMON_EXPECTED_FRACTIONS.to_be_bytes());
        if authenticated {
            raw.extend_from_slice([MBZ_VALUE; 8].as_slice());
        }
        raw.extend_from_slice(&COMMON_EXPECTED_SEQUENCE.to_be_bytes());
        if authenticated {
            raw.extend_from_slice([MBZ_VALUE; 12].as_slice());
        }
        raw.extend_from_slice(&COMMON_EXPECTED_SENT_SECONDS.to_be_bytes());
        raw.extend_from_slice(&COMMON_EXPECTED_SENT_FRACTIONS.to_be_bytes());
        raw.extend_from_slice(&[0x0]);
        raw.extend_from_slice(&[0x1]);
        if authenticated {
            raw.extend_from_slice([MBZ_VALUE; 6].as_slice());
        } else {
            raw.extend_from_slice([MBZ_VALUE; 2].as_slice());
        }
        raw.extend_from_slice(&[0x17]);
        if authenticated {
            raw.extend_from_slice([MBZ_VALUE; 15].as_slice());
        } else {
            raw.extend_from_slice([MBZ_VALUE; 3].as_slice());
        }

        let deserialized = TryInto::<StampResponseBodyType>::try_into(raw.as_slice());

        if let Err(e) = deserialized {
            panic!("Did not deserialize properly: {e}");
        }

        let deserialized = deserialized.unwrap();
        if deserialized != expected {
            panic!("The deserialized version of the stamp response message does not match the serialized version!");
        }
    }

    #[test]
    fn simple_stamp_response_deserialize_authenticated() {
        do_simple_stamp_response_deserialize(true);
    }

    #[test]
    fn simple_stamp_response_deserialize_unauthenticated() {
        do_simple_stamp_response_deserialize(false);
    }

    fn do_simple_stamp_response_roundtrip(authenticated: bool) {
        let body = StampResponseBody {
            received_time: ntp::NtpTime {
                seconds: COMMON_EXPECTED_SECONDS,
                fractions: COMMON_EXPECTED_FRACTIONS,
            },
            sent_sequence: COMMON_EXPECTED_SEQUENCE,
            sent_time: ntp::NtpTime {
                seconds: COMMON_EXPECTED_SENT_SECONDS,
                fractions: COMMON_EXPECTED_SENT_FRACTIONS,
            },
            sent_error: Default::default(),
            received_ttl: COMMON_EXPECTED_TTL,
        };

        let src = if authenticated {
            StampResponseBodyType::Authenticated(body)
        } else {
            StampResponseBodyType::UnAuthenticated(body)
        };

        let serialized_src = Into::<Vec<u8>>::into(&src);

        let result = TryInto::<StampResponseBodyType>::try_into(serialized_src.as_slice());

        if let Err(e) = result {
            panic!("Did not deserialize properly: {e}");
        }

        let result = result.unwrap();
        if result != src {
            panic!("The deserialized version of the stamp response message does not match the serialized version!");
        }
    }

    #[test]
    fn simple_stamp_response_roundtrip_authenticated() {
        do_simple_stamp_response_roundtrip(true);
    }

    #[test]
    fn simple_stamp_response_roundtrip_unauthenticated() {
        do_simple_stamp_response_roundtrip(false);
    }
}
