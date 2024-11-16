/*
 * Teaparty - a STAMP protocol implementation
 * Copyright (C) 2024  Will Hawkins and Cerfcast
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

use crate::ntp::{self, ErrorEstimate, NtpError, NtpTime};
use crate::parameters::TestArgumentKind;
use crate::tlv::{self, MalformedTlv, Tlv};

use std::fmt::{Debug, Display};
use std::io::Error;

pub const UNAUTHENTICATED_STAMP_PKT_SIZE: usize = 44; // in octets

pub const MBZ_VALUE: u8 = 0x00;

pub enum StampError {
    Other(String),
    MissingRequiredArgument(TestArgumentKind),
    Ntp(NtpError),
    Io(std::io::Error),
}

impl From<NtpError> for StampError {
    fn from(value: NtpError) -> Self {
        Self::Ntp(value)
    }
}

impl From<std::io::Error> for StampError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl Display for StampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StampError::Other(s) => write!(f, "Other Stamp error: {}", s),
            StampError::Io(e) => write!(f, "IO error: {}", e),
            StampError::Ntp(e) => write!(f, "NTP error: {}", e),
            StampError::MissingRequiredArgument(arg) => {
                write!(f, "An argument for a test was missing: {:?}", arg)
            }
        }
    }
}

impl Debug for StampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Hash, Eq)]
pub struct Mbz<const L: usize, const V: u8> {}

impl<const L: usize, const V: u8> TryFrom<&[u8]> for Mbz<L, V> {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if !value.iter().all(|b| *b == V) {
            Err(StampError::Other(
                format!("MBZ bytes were not all {}", V).to_string(),
            ))
        } else {
            Ok(Self {})
        }
    }
}

impl<const L: usize, const V: u8> From<&Mbz<L, V>> for [u8; L] {
    fn from(_: &Mbz<L, V>) -> Self {
        [V; L]
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StampResponseContents {
    pub received_time: ntp::NtpTime,
    pub sent_sequence: u32,
    pub sent_time: ntp::NtpTime,
    pub sent_error: ntp::ErrorEstimate,
    pub mbz_1: Mbz<2, MBZ_VALUE>,
    pub received_ttl: u8,
    pub mbz_2: Mbz<3, MBZ_VALUE>,
}

impl TryFrom<&[u8]> for StampResponseContents {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 28 {
            return Err(StampError::Other(
                "Could not parse a Stamp response contents with an invalid size.".to_string(),
            ));
        }

        Ok(StampResponseContents {
            received_time: ntp::NtpTime::try_from(&value[0..8]).map_err(Into::<NtpError>::into)?,
            sent_sequence: u32::from_be_bytes(
                value[8..12]
                    .try_into()
                    .map_err(|_| Error::from(std::io::ErrorKind::InvalidData))?,
            ),
            sent_time: ntp::NtpTime::try_from(&value[12..20])?,
            sent_error: ntp::ErrorEstimate::try_from(&value[20..22])?,
            mbz_1: Mbz::<2, MBZ_VALUE>::try_from(&value[22..24])?,
            received_ttl: value[24],
            mbz_2: Mbz::<3, MBZ_VALUE>::try_from(&value[25..28])?,
        })
    }
}

impl From<&StampResponseContents> for Vec<u8> {
    fn from(value: &StampResponseContents) -> Self {
        let mut result = vec![0u8; 28];
        result[0..8].copy_from_slice(&Into::<Vec<u8>>::into(&value.received_time));
        result[8..12].copy_from_slice(&value.sent_sequence.to_be_bytes());
        result[12..20].copy_from_slice(&Into::<Vec<u8>>::into(&value.sent_time));
        result[20..22].copy_from_slice(&Into::<Vec<u8>>::into(&value.sent_error));
        result[22..24].copy_from_slice(&Into::<[u8; 2]>::into(&value.mbz_1));
        result[24] = value.received_ttl;
        result[25..28].copy_from_slice(&Into::<[u8; 3]>::into(&value.mbz_2));
        result
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StampMsgBody {
    Response(StampResponseContents),
    Mbz(Mbz<28, MBZ_VALUE>),
}

impl StampMsgBody {
    pub const RawSize: usize = 28;
}

impl Default for StampMsgBody {
    fn default() -> Self {
        StampMsgBody::Mbz(Default::default())
    }
}

impl TryFrom<&[u8]> for StampMsgBody {
    type Error = StampError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(mbz) = TryInto::<Mbz<28, MBZ_VALUE>>::try_into(value) {
            Ok(Self::Mbz(mbz))
        } else if let Ok(body) = TryInto::<StampResponseContents>::try_into(value) {
            Ok(Self::Response(body))
        } else {
            Err(StampError::Other(
                "Could not parse the bytes of the message's body into an MBZ or a stamp response."
                    .to_string(),
            ))
        }
    }
}

impl From<StampMsgBody> for Vec<u8> {
    fn from(value: StampMsgBody) -> Vec<u8> {
        match value {
            StampMsgBody::Mbz(mbz) => Into::<[u8; 28]>::into(&mbz).to_vec(),
            StampMsgBody::Response(response) => (&response).into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Ssid {
    Mbz(Mbz<2, MBZ_VALUE>),
    Ssid(u16),
}

impl Ssid {
    pub const RawSize: usize = 2;
}

impl Default for Ssid {
    fn default() -> Self {
        Self::Mbz(Mbz::<2, MBZ_VALUE> {})
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
            Ssid::Ssid(s) => write!(f, "0x{:02x}", s),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StampMsg {
    pub sequence: u32,
    pub time: ntp::NtpTime,
    pub error: ntp::ErrorEstimate,
    pub ssid: Ssid,
    pub body: StampMsgBody,
    pub tlvs: Vec<tlv::Tlv>,
    pub malformed: Option<tlv::MalformedTlv>,
}

impl StampMsg {
    pub fn handle_invalid_tlv_request_flags(&mut self) {
        let invalid_tlvs = if let Some(first_bad) = self
            .tlvs
            .clone()
            .into_iter()
            .position(|tlv| !tlv.is_valid_request())
        {
            self.tlvs.split_off(first_bad)
        } else {
            vec![]
        };

        invalid_tlvs.into_iter().for_each(|invalid| {
            if let Some(malformed) = self.malformed.as_mut() {
                malformed.add_malformed_tlv(invalid);
            } else {
                self.malformed = Some(MalformedTlv {
                    reason: tlv::Error::InvalidFlag(Default::default()),
                    bytes: invalid.into(),
                });
            }
        });
    }
}

impl From<StampMsg> for Vec<u8> {
    fn from(value: StampMsg) -> Self {
        let mut result = vec![0u8; 44];
        result[0..4].copy_from_slice(&value.sequence.to_be_bytes());
        result[4..12].copy_from_slice(&Into::<Vec<u8>>::into(&value.time));
        result[12..14].copy_from_slice(&Into::<Vec<u8>>::into(value.error));
        result[14..16].copy_from_slice(&Into::<Vec<u8>>::into(value.ssid));
        result[16..44].copy_from_slice(&Into::<Vec<u8>>::into(value.body));
        for tlv in value.tlvs {
            result.extend_from_slice(Into::<Vec<u8>>::into(tlv).as_slice());
        }
        value
            .malformed
            .iter()
            .for_each(|mal| result.extend_from_slice(Into::<Vec<u8>>::into(mal).as_slice()));
        result
    }
}

impl TryFrom<&[u8]> for StampMsg {
    type Error = StampError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < UNAUTHENTICATED_STAMP_PKT_SIZE {
            return Err(StampError::Other("Packet is too short".to_string()));
        }

        let mut raw_idx: usize = 0;
        let sequence = u32::from_be_bytes(
            raw[0..4]
                .try_into()
                .map_err(|_| StampError::Other("Invalid sequence number.".to_string()))?,
        );
        raw_idx += 4;

        let time: NtpTime = raw[raw_idx..raw_idx + NtpTime::RawSize].try_into()?;
        raw_idx += 8;

        let ee: ErrorEstimate = raw[raw_idx..raw_idx + ErrorEstimate::RawSize].try_into()?;
        raw_idx += 2;

        let ssid: Ssid = raw[raw_idx..raw_idx + Ssid::RawSize].try_into()?;
        raw_idx += 2;

        // Let's see whether these bytes are 0s. If they are, then we move on.
        // Otherwise, we will have to parse a response message!

        let body = TryInto::<StampMsgBody>::try_into(&raw[raw_idx..raw_idx + StampMsgBody::RawSize])?;
        raw_idx += 28;

        // Only now do we have to worry about not having enough data!
        let mut tlvs: Vec<tlv::Tlv> = vec![];

        let mut malformed: Option<MalformedTlv> = None;
        while raw_idx < raw.len() {
            match TryInto::<tlv::Tlv>::try_into(&raw[raw_idx..]) {
                Ok(tlv) => {
                    raw_idx += tlv.length as usize + Tlv::FtlSize;
                    tlvs.push(tlv);
                }
                Err(reason) => {
                    malformed = Some(MalformedTlv {
                        reason,
                        bytes: raw[raw_idx..].to_vec(),
                    });
                    break;
                }
            }
        }

        Ok(StampMsg {
            sequence,
            time,
            error: ee,
            ssid,
            body,
            tlvs,
            malformed,
        })
    }
}

#[cfg(test)]
mod stamp_test {

    use ntp::NtpTime;

    use super::*;
    #[test]
    fn simple_stamp_from_bytes_test() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE];
        let expected_sequence: u32 = 5;
        let expected_seconds: u32 = 6;
        let expected_fracs: u32 = 7;
        let expected_scale: u8 = 0;
        let expected_multiple: u8 = 2;
        let expected_ssid: u16 = 254;

        raw_data[0..4].copy_from_slice(&u32::to_be_bytes(expected_sequence));
        raw_data[4..8].copy_from_slice(&u32::to_be_bytes(expected_seconds));
        raw_data[8..12].copy_from_slice(&u32::to_be_bytes(expected_fracs));
        raw_data[12] = 0x80;
        raw_data[13] = 0x02;
        raw_data[14..16].copy_from_slice(&u16::to_be_bytes(expected_ssid));
        raw_data[16..44].copy_from_slice([MBZ_VALUE; 28].as_slice());

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

        if stamp_pkt.error.scale != expected_scale {
            panic!(
                "Incorrect error scale. Got {}, wanted {}.",
                stamp_pkt.error.scale, expected_scale
            );
        }

        if stamp_pkt.error.multiple != expected_multiple {
            panic!(
                "Incorrect error multiple. Got {}, wanted {}.",
                stamp_pkt.error.multiple, expected_multiple
            );
        }

        if !stamp_pkt.error.synchronized {
            panic!("Incorrect error synchronized status. Got false, wanted true.");
        }

        match stamp_pkt.ssid {
            Ssid::Mbz(_) => panic!("Incorrect error synchronized status. Got false, wanted true."),
            Ssid::Ssid(ssid) => {
                if ssid != expected_ssid {
                    panic!("Incorrect ssid. Wanted {}, got {}", expected_ssid, ssid);
                }
            }
        }
    }

    #[test]
    fn simple_stamp_malformed_tlv_invalid_flags() {
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

        let mut stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!((stamp_pkt.malformed.is_none()));

        stamp_pkt.handle_invalid_tlv_request_flags();

        assert!((stamp_pkt.malformed.is_some()));
        assert!(stamp_pkt.tlvs.len() == 0);
    }

    #[test]
    fn simple_stamp_malformed_tlv_invalid_flags_before_malformed_tlv() {
        let mut raw_data: [u8; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + (1 + 1 + 2 + 8)] =
            [0; UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + (1 + 1 + 2 + 8)];
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
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE/* + 0*/] = 0x40;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 1] = 0xfe;
        // TLV Length
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 2..UNAUTHENTICATED_STAMP_PKT_SIZE + 4]
            .copy_from_slice(&u16::to_be_bytes(8));
        // TLV Data
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + 4..UNAUTHENTICATED_STAMP_PKT_SIZE + 12]
            .copy_from_slice(&u64::to_be_bytes(0x1122334455667788));

        // TLV Flag
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) /* + 0*/] = 0x20;
        // TLV Type
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + 1] = 0xfe;
        // TLV Length
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + 2
            ..UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + 4]
            .copy_from_slice(&u16::to_be_bytes(9));
        // TLV Data
        raw_data[UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + 4
            ..UNAUTHENTICATED_STAMP_PKT_SIZE + (1 + 1 + 2 + 8) + 12]
            .copy_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let mut stamp_pkt: StampMsg = raw_data
            .as_slice()
            .try_into()
            .expect("Stamp packet parsing unexpectedly failed");

        assert!(stamp_pkt.tlvs.len() == 1);
        assert!((stamp_pkt.malformed.is_some()));

        let malformed = stamp_pkt.malformed.clone().unwrap();
        assert!(malformed.bytes.len() == (1 + 1 + 2 + 8));

        stamp_pkt.handle_invalid_tlv_request_flags();

        assert!((stamp_pkt.malformed.is_some()));
        assert!(stamp_pkt.tlvs.len() == 0);
        let malformed = stamp_pkt.malformed.unwrap();
        assert!(malformed.bytes.len() == 2 * (1 + 1 + 2 + 8));
    }

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

        assert!((stamp_pkt.malformed.is_some()));

        let malformed = stamp_pkt.malformed.unwrap();

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

        assert!((stamp_pkt.malformed.is_some()));

        let malformed = stamp_pkt.malformed.unwrap();

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

        assert!((stamp_pkt.malformed.is_some()));

        let malformed = stamp_pkt.malformed.unwrap();

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

        assert!((stamp_pkt.malformed.is_some()));

        let malformed = stamp_pkt.malformed.unwrap();

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

        if stamp_pkt.tlvs.len() != 1 {
            panic!("Got {} tlvs, expected 1", stamp_pkt.tlvs.len());
        }

        let parsed_tlv = stamp_pkt.tlvs[0].clone();
        if parsed_tlv.flags.get_raw() != 0x20 {
            panic!("Got {} flags, expected 0x20", parsed_tlv.flags);
        }
        if parsed_tlv.tpe != 0xfe {
            panic!("Got {} type, expected 0xfe", parsed_tlv.tpe);
        }
        if parsed_tlv.length != 0x8 {
            panic!("Got {} length, expected 0x8", parsed_tlv.length);
        }

        let contents = u64::from_be_bytes(parsed_tlv.value.clone().try_into().unwrap());
        if contents != 0x1122334455667788 {
            panic!("Got {} contents, expected 0x1122334455667788", contents);
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

        let tlvs = [tlv::Tlv::extra_padding(12)];
        let msg = StampMsg {
            time: NtpTime {
                seconds: 0x5,
                fractions: 0x6,
            },
            sequence: 0x11,
            error: Default::default(),
            ssid: Default::default(),
            body: Default::default(),
            tlvs: tlvs.to_vec(),
            malformed: None,
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

    use ntp::ErrorEstimate;

    use super::*;

    #[test]
    fn simple_stamp_response_deserialize() {
        let expected = StampResponseContents {
            received_time: ntp::NtpTime {
                seconds: 0x5,
                fractions: 0x6,
            },
            sent_sequence: 0x12,
            sent_time: ntp::NtpTime {
                seconds: 0x7,
                fractions: 0x8,
            },
            mbz_1: Default::default(),
            sent_error: Default::default(),
            received_ttl: 0x17,
            mbz_2: Default::default(),
        };

        let mut raw = vec![0u8; 28];

        raw[0..4].copy_from_slice(&0x5u32.to_be_bytes());
        raw[4..8].copy_from_slice(&0x6u32.to_be_bytes());
        raw[8..12].copy_from_slice(&0x12u32.to_be_bytes());
        raw[12..16].copy_from_slice(&0x7u32.to_be_bytes());
        raw[16..20].copy_from_slice(&0x8u32.to_be_bytes());
        raw[20] = 0x0;
        raw[21] = 0x1;
        raw[22..24].copy_from_slice([MBZ_VALUE; 2].as_slice());
        raw[24] = 0x17;
        raw[25..28].copy_from_slice([MBZ_VALUE; 3].as_slice());

        let deserialized = TryInto::<StampResponseContents>::try_into(raw.as_slice());

        if let Err(e) = deserialized {
            panic!("Did not deserialize properly: {}", e);
        }

        let deserialized = deserialized.unwrap();
        if deserialized != expected {
            panic!("The deserialized version of the stamp response message does not match the serialized version!");
        }
    }

    #[test]
    fn simple_stamp_response_roundtrip() {
        let src = StampResponseContents {
            received_time: ntp::NtpTime {
                seconds: 0x5,
                fractions: 0x5,
            },
            sent_sequence: 0x12,
            sent_time: ntp::NtpTime {
                seconds: 0x6,
                fractions: 0x6,
            },
            sent_error: ErrorEstimate {
                synchronized: true,
                scale: 15,
                multiple: 27,
            },
            mbz_1: Default::default(),
            received_ttl: 0x17,
            mbz_2: Default::default(),
        };

        let serialized_src = Into::<Vec<u8>>::into(&src);

        let result = TryInto::<StampResponseContents>::try_into(serialized_src.as_slice());

        if let Err(e) = result {
            panic!("Did not deserialize properly: {}", e);
        }

        let result = result.unwrap();
        if result != src {
            panic!("The deserialized version of the stamp response message does not match the serialized version!");
        }
    }
}
