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

use chrono::prelude::Utc;
use chrono::TimeZone;
use clap::Error;

use std::fmt::Debug;
use std::fmt::Display;

pub enum NtpError {
    InvalidData(String),
}

impl Debug for NtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => Debug::fmt(msg, f),
        }
    }
}

impl Display for NtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NtpTime {
    pub seconds: u32,
    pub fractions: u32,
}

const NANOSECONDS_PER_SECOND: u64 = 1000000000u64;

impl NtpTime {
    pub const RawSize: usize = 8;

    pub fn now() -> Self {
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        let now = Utc::now();
        let difference = now.signed_duration_since(then);

        Self::from_nanos(difference.num_nanoseconds().unwrap() as u64)
    }

    pub fn from_nanos(src_nanos: u64) -> NtpTime {
        let seconds_in_nanos = src_nanos / NANOSECONDS_PER_SECOND;

        let mut nanos = src_nanos - (seconds_in_nanos * NANOSECONDS_PER_SECOND);
        // Goal: Convert the number of nanoseconds to a fraction of seconds. The fraction
        // is in units of 1/(2^32). So, if there are NANOSECONDS_PER_SECOND nanoseconds
        // per second, then nanos/NANOSECONDS_PER_SECOND is the fractions of a second. To
        // convert that into units of 1/(2^32), we multiply by 2^32. Because * is commutative,
        // we can do them in any order, so we will do the multiply first and the divide second.
        // Notes taken from: https://tickelton.gitlab.io/articles/ntp-timestamps/
        nanos <<= 32;
        nanos /= NANOSECONDS_PER_SECOND;

        NtpTime {
            seconds: seconds_in_nanos as u32,
            fractions: nanos as u32,
        }
    }
}

impl From<chrono::DateTime<Utc>> for NtpTime {
    fn from(value: chrono::DateTime<Utc>) -> Self {
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        let difference = value.signed_duration_since(then);
        NtpTime::from_nanos(difference.num_nanoseconds().unwrap() as u64)
    }
}

impl TryFrom<&[u8]> for NtpTime {
    type Error = NtpError;
    fn try_from(raw: &[u8]) -> Result<NtpTime, Self::Error> {
        if raw.len() < 8 {
            return Err(NtpError::InvalidData(
                "NTP raw data was too short".to_string(),
            ));
        }
        let seconds = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let fractions = u32::from_be_bytes(raw[4..8].try_into().unwrap());

        Ok(NtpTime { seconds, fractions })
    }
}

#[test]
fn test_simple_ntp_conversion() {
    // Based upon the test code from the Apache Commons (file: )
    // > For example, Tue, Dec 17 2002 09:07:24.810 EST is represented by a single Java-based time value
    // > of f22cd1fc8a, but its NTP equivalent are all values ranging from c1a9ae1c.cf5c28f5 to c1a9ae1c.cf9db22c.
    // So, that's our test case.
    let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
    // Build Dec 17 2002 09:07:24.810 EST
    let test = Utc.with_ymd_and_hms(2002, 12, 17, 14, 7, 24).unwrap();
    let extra_nanos = (0.810f64 * NANOSECONDS_PER_SECOND as f64) as i64;

    let difference = test.signed_duration_since(then).num_nanoseconds().unwrap() + extra_nanos;
    let result = NtpTime::from_nanos(difference as u64);

    let expected_seconds = 0xc1a9ae1cu32;
    let expected_fractions = 0xcf5c28f5u32;
    if result.seconds != expected_seconds {
        panic!(
            "Expected {:x} seconds but got {:x}",
            expected_seconds, result.seconds
        );
    }
    if result.fractions != expected_fractions {
        panic!(
            "Expected {:x} fractions but got {:x}",
            expected_fractions, result.fractions
        );
    }
}

#[test]
fn test_now_ntp_conversion() {
    // This is more of a tool to help us visualize the NTP timestamp.
    let ntp_now = NtpTime::now();
    println!("ntp_now: {:?}", ntp_now);
}

impl From<&NtpTime> for Vec<u8> {
    fn from(raw: &NtpTime) -> Vec<u8> {
        let mut result = vec![0u8; 8];
        result[0..4].copy_from_slice(&raw.seconds.to_be_bytes());
        result[4..8].copy_from_slice(&raw.fractions.to_be_bytes());

        result
    }
}

impl From<NtpTime> for Vec<u8> {
    fn from(raw: NtpTime) -> Vec<u8> {
        (&raw).into()
    }
}

#[test]
fn simple_ntp_roundtrip_test() {
    let mut raw_data: [u8; 8] = [0; 8];
    raw_data[0..4].copy_from_slice(&u32::to_be_bytes(5));
    raw_data[4..8].copy_from_slice(&u32::to_be_bytes(6));

    let ntp_time: Result<NtpTime, NtpError> = raw_data.as_slice().try_into();

    if ntp_time.is_err() {
        panic!(
            "Should have been able to convert: {}",
            ntp_time.unwrap_err()
        );
    }

    let ntp_time = ntp_time.unwrap();
    assert_eq!(ntp_time.seconds, 5);
    assert_eq!(ntp_time.fractions, 6);

    let ntp_time_serialized: Vec<u8> = ntp_time.into();

    assert!(raw_data[0..4].eq(&ntp_time_serialized[0..4]));
    assert!(raw_data[4..8].eq(&ntp_time_serialized[4..8]));
}

#[derive(Clone, Debug, PartialEq)]
pub struct ErrorEstimate {
    pub scale: u8,
    pub multiple: u8,
    pub synchronized: bool,
    // Note: Z is not tracked -- we only implement the NTP format at this time.
}

impl ErrorEstimate {
    pub const RawSize: usize = 2;
}

impl Default for ErrorEstimate {
    fn default() -> Self {
        Self {
            scale: 0,
            multiple: 1,
            synchronized: false,
        }
    }
}

impl TryFrom<&[u8]> for ErrorEstimate {
    type Error = NtpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value[1] == 0x0 {
            Err(NtpError::InvalidData(
                "Cannot have zero multiplier in error-estimate field.".to_string(),
            ))
        } else if value[0] & 0x40 != 0 {
            Err(NtpError::InvalidData(
                "Non NTP timestamps are not supported.".to_string(),
            ))
        } else {
            Ok(Self {
                synchronized: value[0] & 0x80 != 0,
                scale: value[0] & 0x3f,
                multiple: value[1],
            })
        }
    }
}

impl From<&ErrorEstimate> for Vec<u8> {
    fn from(value: &ErrorEstimate) -> Self {
        let mut result = vec![0u8; 2];
        result[0] = if value.synchronized { 0x80 } else { 0x00 };
        result[0] |= value.scale & 0x3F;
        result[1] = value.multiple;
        result
    }
}

impl From<ErrorEstimate> for Vec<u8> {
    fn from(value: ErrorEstimate) -> Self {
        From::<&ErrorEstimate>::from(&value)
    }
}

#[cfg(test)]
mod error_estimate_test {
    use super::*;

    #[test]
    pub fn test_serialization() {
        let ee = ErrorEstimate {
            synchronized: true,
            scale: 0x5,
            multiple: 0x12,
        };

        let serialized_ee = Into::<Vec<u8>>::into(ee);

        if serialized_ee[0] & 0x80 == 0x0 {
            panic!("Did not serialize the synchronized flag correctly");
        }
        if serialized_ee[0] & 0x3f != 0x5 {
            panic!("Did not serialize the scale value correctly");
        }
        if serialized_ee[1] != 0x12 {
            panic!("Did not serialize the scale value correctly");
        }
    }

    #[test]
    pub fn test_deserialization() {
        let raw_ee = [0x85u8, 0x12u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_err() {
            panic!("Should have been able to parse the raw bytes into a valid error estimate.")
        }

        let parsed_ee = parsed_ee.unwrap();
        if !parsed_ee.synchronized {
            panic!("Did not deserialize the synchronized flag correctly");
        }
        if parsed_ee.scale != 0x5 {
            panic!("Did not serialize the scale value correctly");
        }
        if parsed_ee.multiple != 0x12 {
            panic!("Did not serialize the multiple value correctly");
        }
    }

    #[test]
    pub fn test_invalid_raw_ee() {
        let raw_ee = [85u8, 0u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_ok() {
            panic!("Should _not_ have been able to parse the raw bytes into a valid error estimate but could.")
        }
    }

    #[test]
    pub fn test_non_ntp_time() {
        let raw_ee = [0xffu8, 0xffu8];

        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_ok() {
            panic!("Parsing raw error estimate bytes that indicate a non-NTP time format should not work, but did.")
        }
    }
}
