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

use std::{
    fmt::Debug,
    fmt::Display,
    ops::{BitAnd, BitOr},
    result::Result,
};

#[derive(Clone, PartialEq)]
pub enum Error {
    InvalidFlag(String),
    NotEnoughData,
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidFlag(r) => write!(f, "Invalid TLV flag: {}", r),
            Error::NotEnoughData => write!(f, "TLV length exceeded available data"),
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
            "Flags: Unrecognized: {}, Integrity: {}, Malformed: {}",
            self.get_unrecognized(),
            self.get_integrity(),
            self.get_malformed()
        )
    }
}

impl Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
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

#[derive(Debug, Clone, PartialEq)]
pub struct MalformedTlv {
    pub reason: Error,
    pub bytes: Vec<u8>,
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

#[derive(Clone, Debug, PartialEq)]
pub struct Tlv {
    pub flags: Flags,
    pub tpe: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

/// Convert from a &Tlv into a vector of bytes.
impl From<&Tlv> for Vec<u8> {
    fn from(raw: &Tlv) -> Vec<u8> {
        let mut result = vec![0u8; 1 + 1 + 2 + raw.length as usize];
        result[0] = raw.flags.clone().into();
        result[1] = raw.tpe;
        result[2..4].copy_from_slice(&raw.length.to_be_bytes());
        result[4..4 + raw.length as usize].copy_from_slice(raw.value.as_slice());
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

impl Tlv {
    pub const HEARTBEAT: u8 = 176;
    pub const DESTINATION_PORT: u8 = 177;
    pub const TIMESTAMP: u8 = 3;
    pub const PADDING: u8 = 1;
    pub const DSCPECN: u8 = 179;

    /// Make a Tlv for padding.
    pub fn extra_padding(len: u16) -> Self {
        Tlv {
            flags: Flags::new(),
            tpe: Tlv::PADDING,
            length: len,
            value: vec![0u8; len as usize],
        }
    }

    pub fn heartbeat() -> Self {
        Tlv {
            flags: Flags::new_request(),
            tpe: Tlv::HEARTBEAT,
            length: 8,
            value: vec![0u8; 8],
        }
    }

    pub fn unrecognized(len: u16) -> Self {
        let mut unrecognized = Self::extra_padding(len);
        unrecognized.tpe = 0xff;
        unrecognized
    }

    pub fn is_valid_request(&self) -> bool {
        self.flags.get_unrecognized() && !self.flags.get_integrity() && !self.flags.get_malformed()
    }
}
