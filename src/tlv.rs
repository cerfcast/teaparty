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

use std::{
    fmt::Debug,
    ops::{BitAnd, BitOr},
    result::Result,
};

use crate::{custom_handlers::CustomHandlers, os::MacAddr, stamp::StampError};

#[derive(Clone, PartialEq)]
pub enum Error {
    InvalidFlag(String),
    NotEnoughData,
    FieldNotZerod(String),
    FieldWrongSized(String, usize, usize),
    FieldValueInvalid(String),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFlag(r) => write!(f, "Invalid TLV flag: {}", r),
            Error::NotEnoughData => write!(f, "TLV length exceeded available data"),
            Error::FieldNotZerod(field) => write!(f, "TLV field named {} was not zerod.", field),
            Error::FieldWrongSized(field, wanted, got) => write!(
                f,
                "TLV field named {} was the wrong size: wanted {} but got {}.",
                field, wanted, got
            ),
            Error::FieldValueInvalid(field) => {
                write!(f, "TLV field named {} had invalid value.", field)
            }
        }
    }
}

#[derive(Clone, PartialEq, Default)]
pub struct Flags {
    value: u8,
}

fn and<T>(left: T, right: T) -> T
where
    T: BitAnd<Output = T>,
{
    left & right
}

fn or<T>(left: T, right: T) -> T
where
    T: BitOr<Output = T>,
{
    left | right
}

impl Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unrecognized: {}, Integrity: {}, Malformed: {}",
            self.get_unrecognized(),
            self.get_integrity(),
            self.get_malformed()
        )
    }
}

impl Flags {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn new_request() -> Self {
        Self { value: 0x80 }
    }

    pub fn new_response() -> Self {
        Self { value: 0x20 }
    }

    pub fn set_unrecognized(&mut self, on: bool) {
        let mut flag_value = 0x80u8;
        let mut op: fn(u8, u8) -> u8 = or;

        if !on {
            flag_value = !flag_value;
            op = and;
        }
        self.value = op(self.value, flag_value)
    }

    pub fn get_unrecognized(&self) -> bool {
        self.value & 0x80 != 0
    }

    pub fn set_malformed(&mut self, on: bool) {
        let mut flag_value = 0x40u8;
        let mut op: fn(u8, u8) -> u8 = or;

        if !on {
            flag_value = !flag_value;
            op = and;
        }
        self.value = op(self.value, flag_value)
    }
    pub fn get_malformed(&self) -> bool {
        self.value & 0x40 != 0
    }

    pub fn set_integrity(&mut self, on: bool) {
        let mut flag_value = 0x20u8;
        let mut op: fn(u8, u8) -> u8 = or;

        if !on {
            flag_value = !flag_value;
            op = and;
        }
        self.value = op(self.value, flag_value)
    }
    pub fn get_integrity(&self) -> bool {
        self.value & 0x20 != 0
    }

    pub fn get_raw(&self) -> u8 {
        self.value
    }
}

impl From<&Flags> for u8 {
    fn from(value: &Flags) -> Self {
        value.value
    }
}

impl From<Flags> for u8 {
    fn from(value: Flags) -> Self {
        From::from(&value)
    }
}

impl TryFrom<u8> for Flags {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value & 0x1F != 0 {
            return Err(Error::InvalidFlag(
                "Reserved bits contain non-zero data".into(),
            ));
        }
        Ok(Self { value })
    }
}

#[cfg(test)]
mod test {
    use super::Error;
    use super::Flags;
    #[test]
    fn test_flag_umi() {
        let v: u8 = 0x80 | 0x40 | 0x20;
        let f: Flags = v.try_into().unwrap();

        assert!(f.get_unrecognized());
        assert!(f.get_malformed());
        assert!(f.get_integrity());
    }

    #[test]
    fn test_flag_reserved_bits() {
        let value = 0x90;
        let result = TryInto::<Flags>::try_into(value);
        assert!(matches!(result, Err(Error::InvalidFlag(_))));
    }

    #[test]
    fn test_u8_umi() {
        let mut f: Flags = Flags::new();

        f.set_unrecognized(true);
        f.set_malformed(true);
        f.set_integrity(true);

        assert!(Into::<u8>::into(f) == (0x80u8 | 0x40u8 | 0x20u8));
    }

    #[test]
    fn test_flag_alone() {
        let mut f: Flags = Flags::new();
        f.set_unrecognized(true);
        assert!(f.get_unrecognized());

        let mut f: Flags = Flags::new();
        f.set_malformed(true);
        assert!(f.get_malformed());

        let mut f: Flags = Flags::new();
        f.set_integrity(true);
        assert!(f.get_integrity());
    }

    #[test]
    fn test_u8_flip() {
        let mut f: Flags = Flags::new();

        f.set_unrecognized(true);
        f.set_malformed(true);
        f.set_integrity(true);
        assert!(Into::<u8>::into(f.clone()) == (0x80u8 | 0x40u8 | 0x20u8));

        f.set_unrecognized(true);
        f.set_malformed(false);
        f.set_integrity(true);
        assert!(Into::<u8>::into(f.clone()) == (0x80u8 | 0x20u8));

        f.set_unrecognized(false);
        f.set_malformed(false);
        f.set_integrity(true);
        assert!(Into::<u8>::into(f.clone()) == (0x20u8));

        f.set_unrecognized(false);
        f.set_malformed(false);
        f.set_integrity(false);
        assert!(Into::<u8>::into(f) == 0x0u8);
    }
}

#[derive(Clone, PartialEq)]
pub struct MalformedTlv {
    pub reason: Error,
    pub bytes: Vec<u8>,
}

impl MalformedTlv {
    pub fn new(reason: Error, bytes: Vec<u8>) -> Self {
        let mut mtv = Self { reason, bytes };
        mtv.make_bytes_parseable();
        mtv
    }
    pub fn make_bytes_parseable(&mut self) {
        let mut malformed_flag = Flags::new();
        malformed_flag.set_malformed(true);
        self.bytes[0] |= Into::<u8>::into(malformed_flag);

        /*
        if self.bytes.len() > Tlv::FtlSize {
            let tlv_length_field_value = (self.bytes.len() - Tlv::FtlSize) as u16;
            self.bytes[2..4].copy_from_slice(&tlv_length_field_value.to_be_bytes());
        }
        */
    }
}

impl Debug for MalformedTlv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MalformedTlv")
            .field("reason", &self.reason)
            .field("bytes", &format_args!("{:x?}", self.bytes))
            .finish()
    }
}

impl From<&MalformedTlv> for Vec<u8> {
    fn from(value: &MalformedTlv) -> Self {
        value.bytes.clone()
    }
}

impl From<MalformedTlv> for Vec<u8> {
    fn from(value: MalformedTlv) -> Self {
        From::<&MalformedTlv>::from(&value)
    }
}

impl MalformedTlv {
    pub fn add_malformed_tlv(&mut self, tlv: Tlv) {
        self.bytes.extend(Into::<Vec<u8>>::into(tlv));
    }
}

#[derive(Clone, PartialEq)]
pub struct Tlv {
    pub flags: Flags,
    pub tpe: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl Debug for Tlv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handlers = CustomHandlers::build();

        let mut printable = f.debug_struct("Tlv");
        printable.field("flags", &self.flags);

        if let Some(handler) = handlers.get_handler(self.tpe) {
            let handler = handler.lock().unwrap();
            printable.field("type", &format_args!("{:?}", handler.tlv_name()));
        } else {
            printable.field("type", &format_args!("{:x?}", self.tpe));
        }

        printable
            .field("length", &self.length)
            .field("value", &format_args!("{:x?}", self.value))
            .finish()
    }
}

impl Tlv {
    #[allow(non_upper_case_globals)]
    pub const FtlSize: usize = 1 + 1 + 2;
}

/// Convert from a &Tlv into a vector of bytes.
impl From<&Tlv> for Vec<u8> {
    fn from(raw: &Tlv) -> Vec<u8> {
        let mut result = vec![0u8; Tlv::FtlSize + raw.value.len()];
        result[0] = raw.flags.clone().into();
        result[1] = raw.tpe;
        result[2..4].copy_from_slice(&raw.length.to_be_bytes());
        result[4..4 + raw.value.len()].copy_from_slice(raw.value.as_slice());
        result
    }
}

/// Convert from a Tlv into a vector of bytes.
impl From<Tlv> for Vec<u8> {
    fn from(raw: Tlv) -> Vec<u8> {
        From::<&Tlv>::from(&raw)
    }
}

/// Try to convert from a slice of bytes into a Tlv.
impl TryFrom<&[u8]> for Tlv {
    type Error = Error;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let mut raw_idx = 0usize;
        let flags: Flags = raw[raw_idx].try_into()?;
        raw_idx += 1;

        if raw_idx >= raw.len() {
            return Err(Error::NotEnoughData);
        }
        let tpe = raw[raw_idx];
        raw_idx += 1;

        if raw_idx + 2 >= raw.len() {
            return Err(Error::NotEnoughData);
        }
        let length = u16::from_be_bytes(raw[raw_idx..raw_idx + 2].try_into().unwrap());
        raw_idx += 2;

        if raw_idx + (length as usize) > raw.len() {
            return Err(Error::NotEnoughData);
        }

        let mut value = vec![0; length as usize];
        value.copy_from_slice(&raw[raw_idx..raw_idx + (length as usize)]);

        Ok(Tlv {
            flags,
            tpe,
            length,
            value,
        })
    }
}

#[cfg(test)]
mod tlv_parse_test {
    use crate::tlv::{Error, Tlv};

    #[test]
    fn simple_stamp_malformed_tlv_test_data_too_short() {
        let mut raw_data: [u8; Tlv::FtlSize + 8] = [0; Tlv::FtlSize + 8];

        // TLV Flag
        raw_data[0] = 0x20;
        // TLV Type
        raw_data[1] = 0xfe;
        // TLV Length: There are only 8 bytes in the "value" of the Tlv, but we say that there are 9.
        raw_data[2..4].copy_from_slice(&u16::to_be_bytes(9));
        // TLV Data
        raw_data[4..12].copy_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let tlv = TryInto::<Tlv>::try_into(raw_data.as_slice());

        assert!(matches!(tlv, Err(Error::NotEnoughData)));
    }
}

impl Tlv {
    pub const HEARTBEAT: u8 = 176;
    pub const DESTINATION_PORT: u8 = 177;
    pub const HISTORY: u8 = 178;
    pub const DSCPECN: u8 = 179;
    pub const PADDING: u8 = 1;
    pub const LOCATION: u8 = 2;
    pub const TIMESTAMP: u8 = 3;
    pub const COS: u8 = 4;
    pub const ACCESSREPORT: u8 = 6;
    pub const FOLLOWUP: u8 = 7;

    /// Make a Tlv for padding.
    pub fn extra_padding(len: u16) -> Self {
        Tlv {
            flags: Flags::new(),
            tpe: Tlv::PADDING,
            length: len,
            value: vec![0u8; len as usize],
        }
    }

    pub fn heartbeat(mac: MacAddr) -> Self {
        let mut macv = mac.mac.to_vec();
        macv.extend(vec![0, 0]);
        Tlv {
            flags: Flags::new_request(),
            tpe: Tlv::HEARTBEAT,
            length: 8,
            value: macv,
        }
    }

    pub fn malformed_request(len: u16) -> Self {
        Self::extra_padding(len)
    }

    pub fn malformed_tlv(len: u16) -> Self {
        let mut long = Self::extra_padding(len);
        long.flags = Flags::new_request();
        long.length = len + 5;
        long
    }

    pub fn unrecognized(len: u16) -> Self {
        let mut unrecognized = Self::extra_padding(len);
        unrecognized.flags = Flags::new_request();
        unrecognized.tpe = 0xff;
        unrecognized
    }

    pub fn is_valid_request(&self) -> bool {
        self.flags.get_unrecognized() && !self.flags.get_integrity() && !self.flags.get_malformed()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tlvs {
    pub tlvs: Vec<Tlv>,
    pub malformed: Option<MalformedTlv>,
}

impl Tlvs {
    pub fn handle_malformed_response(&mut self) {
        let invalid_tlvs = if let Some(first_bad) = self
            .tlvs
            .clone()
            .into_iter()
            .position(|tlv| tlv.flags.get_malformed())
        {
            self.tlvs.split_off(first_bad)
        } else {
            vec![]
        };

        invalid_tlvs.into_iter().for_each(|invalid| {
            if let Some(malformed) = self.malformed.as_mut() {
                malformed.add_malformed_tlv(invalid);
            } else {
                let mut malformed_tlv = invalid.clone();
                malformed_tlv.flags.set_malformed(true);

                self.malformed = Some(MalformedTlv {
                    reason: Error::InvalidFlag(format!("{:?}", invalid.flags).to_string()),
                    bytes: malformed_tlv.into(),
                });
            }
        });
    }
}

impl TryFrom<&[u8]> for Tlvs {
    type Error = StampError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut tlvs: Vec<Tlv> = vec![];

        let mut malformed: Option<MalformedTlv> = None;
        let mut raw_idx = 0usize;
        while raw_idx < value.len() {
            match TryInto::<Tlv>::try_into(&value[raw_idx..]) {
                Ok(tlv) => {
                    // We are _not_ safe: The malformed flag may be set.
                    if !tlv.flags.get_malformed() {
                        raw_idx += tlv.length as usize + Tlv::FtlSize;
                        tlvs.push(tlv);
                    } else {
                        // Even if we were able to parse the TLV, if the
                        // malformed flag is set, we have to bail out.
                        malformed = Some(MalformedTlv::new(
                            Error::InvalidFlag("Malformed is indicated.".to_string()),
                            value[raw_idx..].to_vec(),
                        ));
                        break;
                    }
                }
                Err(reason) => {
                    malformed = Some(MalformedTlv::new(reason, value[raw_idx..].to_vec()));
                    break;
                }
            }
        }
        Ok(Tlvs { tlvs, malformed })
    }
}

impl From<Tlvs> for Vec<u8> {
    fn from(value: Tlvs) -> Self {
        let mut result: Vec<u8> = vec![];

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

#[cfg(test)]
mod tlvs_parse_test {
    use crate::tlv::{Tlv, Tlvs};

    #[test]
    fn simple_stamp_tlvs_test_one_malformed_tlv() {
        let mut inner_raw_data: [u8; Tlv::FtlSize + 8] = [0; Tlv::FtlSize + 8];

        // TLV Flag
        inner_raw_data[0] = 0x20;
        // TLV Type
        inner_raw_data[1] = 0xfe;
        // TLV Length: There are only 8 bytes in the "value" of the Tlv, but we say that there are 9.
        inner_raw_data[2..4].copy_from_slice(&u16::to_be_bytes(9));
        // TLV Data
        inner_raw_data[4..12].copy_from_slice(&u64::to_be_bytes(0));

        let tlvs = TryInto::<Tlvs>::try_into(inner_raw_data.as_slice())
            .expect("Bytes with bad TLV should still parse into TLVs");

        assert!(tlvs.tlvs.is_empty());

        assert!(tlvs.malformed.is_some());

        let malformed = tlvs.malformed.unwrap();
        assert!(malformed.bytes[0] & 0x40 != 0);
    }
}

#[cfg(test)]
mod tlvs_invalid_flags_test {
    use crate::tlv::Tlvs;

    #[test]
    fn simple_stamp_malformed_tlv_invalid_flags() {
        let mut raw_data: Vec<u8> = vec![];

        // TLV Flag
        raw_data.extend_from_slice(&[0x80]);
        // TLV Type
        raw_data.extend_from_slice(&[0xfe]);
        // TLV Length
        raw_data.extend_from_slice(&u16::to_be_bytes(8));
        // TLV Data
        raw_data.extend_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let tlvs: Tlvs = raw_data
            .as_slice()
            .try_into()
            .expect("TLV parsing unexpectedly failed");

        assert!(tlvs.tlvs[0].flags.get_unrecognized());
        assert!((tlvs.malformed.is_none()));
    }

    #[test]
    fn simple_stamp_malformed_tlv_invalid_flags_before_malformed_tlv() {
        let mut raw_data: Vec<u8> = vec![];

        // TLV Flag
        raw_data.extend_from_slice(&[0x40]);
        // TLV Type
        raw_data.extend_from_slice(&[0xfe]);
        // TLV Length
        raw_data.extend_from_slice(&u16::to_be_bytes(8));
        // TLV Data
        raw_data.extend_from_slice(&u64::to_be_bytes(0x1122334455667788));

        // TLV Flag
        raw_data.extend_from_slice(&[0x20]);
        // TLV Type
        raw_data.extend_from_slice(&[0xfe]);
        // TLV Length
        raw_data.extend_from_slice(&u16::to_be_bytes(9));
        // TLV Data
        raw_data.extend_from_slice(&u64::to_be_bytes(0x1122334455667788));

        let mut tlvs: Tlvs = raw_data
            .as_slice()
            .try_into()
            .expect("TLV parsing unexpectedly failed");

        tlvs.handle_malformed_response();

        assert!((tlvs.malformed.is_some()));
        assert!(tlvs.tlvs.is_empty());
        let malformed = tlvs.malformed.unwrap();
        assert!(malformed.bytes.len() == 2 * (1 + 1 + 2 + 8));
    }
}
