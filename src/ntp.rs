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

use chrono::prelude::Utc;
use chrono::TimeZone;
use serde::Serialize;

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

#[derive(Clone, Default, PartialEq, Serialize)]
pub struct NtpTime {
    pub seconds: u32,
    pub fractions: u32,
}

impl Debug for NtpTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtpTime")
            .field("seconds", &format_args!("0x{:x?}", self.seconds))
            .field("fractions", &format_args!("0x{:x?}", self.fractions))
            .field(
                "unix_time",
                &Into::<chrono::DateTime<Utc>>::into(self.clone()),
            )
            .finish()
    }
}
const NANOSECONDS_PER_SECOND: u64 = 1000000000u64;

impl NtpTime {
    #[allow(non_upper_case_globals)]
    pub const RawSize: usize = 8;

    pub fn now() -> Self {
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        let now = Utc::now();
        let difference = now.signed_duration_since(then);

        Self::from_nanos(difference.num_nanoseconds().unwrap() as u64)
    }

    pub fn from_nanos(src_nanos: u64) -> NtpTime {
        let seconds = src_nanos / NANOSECONDS_PER_SECOND;

        let mut nanos = src_nanos - (seconds * NANOSECONDS_PER_SECOND);
        // Goal: Convert the number of nanoseconds to a fraction of seconds. The fraction
        // is in units of 1/(2^32). So, if there are NANOSECONDS_PER_SECOND nanoseconds
        // per second, then nanos/NANOSECONDS_PER_SECOND is the fractions of a second.NTP Time
        // is based on fractions of a second that are 1/2^32. That means that there are a total
        // of 2^32 fractional seconds in a whole second. Multiplying by the fractional nanos/second
        // will get us where we need to go. Because * is commutative,
        // we can do them in any order, so we will do the multiply first and the divide second.
        // Notes taken from: https://tickelton.gitlab.io/articles/ntp-timestamps/
        nanos <<= 32;
        nanos /= NANOSECONDS_PER_SECOND;

        NtpTime {
            seconds: seconds as u32,
            fractions: nanos as u32,
        }
    }

    pub fn to_nanos(ntp_time: NtpTime) -> u64 {
        let nanos = (ntp_time.fractions as u64 * NANOSECONDS_PER_SECOND) >> 32;
        let seconds = ntp_time.seconds as u64 * NANOSECONDS_PER_SECOND;

        seconds + nanos
    }
}

impl From<chrono::DateTime<Utc>> for NtpTime {
    fn from(value: chrono::DateTime<Utc>) -> Self {
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        let difference = value.signed_duration_since(then);
        NtpTime::from_nanos(difference.num_nanoseconds().unwrap() as u64)
    }
}

impl From<NtpTime> for chrono::DateTime<Utc> {
    fn from(value: NtpTime) -> Self {
        let nanos = chrono::Duration::nanoseconds(NtpTime::to_nanos(value) as i64);
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        then + nanos
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

#[cfg(test)]
mod ntptime_tests {

    #[test]
    fn test_simple_ntp_conversion() {
        // Based upon the test code from the Apache Commons (file: )
        // > For example, Tue, Dec 17 2002 09:07:24.810 EST is represented by a single Java-based time value
        // > of f22cd1fc8a, but its NTP equivalent are all values ranging from c1a9ae1c.cf5c28f5 to c1a9ae1c.cf9db22c.
        // So, that's our test case.
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        // Build Dec 17 2002 09:07:24.810 EST (Note: Using hour = 14 because of conversion between EST and GMT)
        let test = Utc.with_ymd_and_hms(2002, 12, 17, 14, 7, 24).unwrap()
            + Duration::from_nanos(810000000);

        let difference = test.signed_duration_since(then).num_nanoseconds().unwrap();
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

    use crate::ntp::NtpTime;
    #[cfg(test)]
    use chrono::DateTime;
    use chrono::{TimeZone, Utc};
    use std::time::Duration;

    fn do_test_simple_ntp_conversion_roundtrip(expected: NtpTime, low_date: DateTime<Utc>) {
        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        let low_nanos = low_date
            .signed_duration_since(then)
            .num_nanoseconds()
            .unwrap();
        let high_nanos = low_nanos + 1;

        let low = NtpTime::from_nanos(low_nanos as u64);
        let high = NtpTime::from_nanos(high_nanos as u64);

        // Seconds should match expected NTP seconds perfectly ...
        if low.seconds != expected.seconds {
            panic!(
                "Expected {:x} seconds but got {:x}",
                expected.seconds, low.seconds
            );
        }
        // and low/high should span the expected NTP fractions.
        if !(low.fractions < expected.fractions && expected.fractions <= high.fractions) {
            // Note: These are inclusive in the case where the next 1/(2^32) fraction
            // of a second would result in the nanosecond increasing by one
            // (see simple_ntp_conversion_from_bytes).
            panic!(
                "Expected {:x} to be between {:x} and {:x}, but it is not",
                expected.fractions, high.fractions, high.fractions
            );
        }

        let then = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
        // Now, "roundtrip" the expected result back to a DateTime and make sure that it is _precisely_
        // the low value (because of truncation)!
        let roundtrip_nanos = then + Duration::from_nanos(NtpTime::to_nanos(expected));
        assert!(roundtrip_nanos == low_date);
    }

    #[test]
    fn test_simple_roundtrip_conversions() {
        let mut test_cases: Vec<(NtpTime, DateTime<Utc>)> = vec![];

        // Test case:
        // NTP Time: 0xebbbe239 seconds and 0x3f83add9 fractions
        // 2025-04-29 at 23:41:45.248103013 UTC and
        let expected = NtpTime {
            seconds: 0xebbbe239u32,
            fractions: 0x3f83add9u32,
        };
        let test = Utc.with_ymd_and_hms(2025, 4, 29, 23, 41, 45).unwrap()
            + Duration::from_nanos(248_103_013);

        test_cases.push((expected, test));

        // Test case:
        // NTP Time: 0xebbd1ff2 seconds and 0x467b0671 fractions
        // 2025-04-30 at 22:17:22.275314714 UTC and
        let expected = NtpTime {
            seconds: 0xebbd1ff2u32,
            fractions: 0x467b0671u32,
        };
        let test = Utc.with_ymd_and_hms(2025, 4, 30, 22, 17, 22).unwrap()
            + Duration::from_nanos(275314714);

        test_cases.push((expected, test));

        // Test case:
        // NTP Time:0xebbd21b6 seconds and 0xd47290df fractions
        // 2025-04-30 at 22:24:54.829873136 UTC and
        let expected = NtpTime {
            seconds: 0xebbd21b6u32,
            fractions: 0xd47290dfu32,
        };
        let test = Utc.with_ymd_and_hms(2025, 4, 30, 22, 24, 54).unwrap()
            + Duration::from_nanos(829873136);

        test_cases.push((expected, test));

        for (expected, test) in test_cases.iter().cloned() {
            do_test_simple_ntp_conversion_roundtrip(expected, test);
        }
    }

    #[test]
    fn test_now_ntp_conversion() {
        // This is more of a tool to help us visualize the NTP timestamp.
        let ntp_now = NtpTime::now();
        println!("ntp_now: {ntp_now:?}");
    }

    #[test]
    fn simple_ntp_conversion_from_bytes() {
        let raw_data: [u8; 8] = [0xeb, 0xbd, 0x17, 0x88, 0x45, 0x75, 0xe9, 0x3f];
        // Between the value in raw_data and [0xeb, 0xbd, 0x17, 0x88, 0x45, 0x75, 0xe9, 0x3f],
        // the number of nanoseconds increases by one. That is not a usual case.

        let expected: NtpTime = raw_data
            .as_slice()
            .try_into()
            .expect("Should have been able to convert into nanoseconds.");

        let time = Utc.with_ymd_and_hms(2025, 4, 30, 21, 41, 28).unwrap()
            + Duration::from_nanos(271_330_430);

        do_test_simple_ntp_conversion_roundtrip(expected, time);
    }
    #[test]
    fn simple_ntp_raw_bytes_roundtrip_test() {
        // Test From for NtpTime <-> Vec<u8> conversions.
        let raw_data: [u8; 8] = [0xeb, 0xbd, 0x17, 0x88, 0x45, 0x75, 0xe9, 0x3f];

        let expected: NtpTime = raw_data
            .as_slice()
            .try_into()
            .expect("Should have been able to convert into nanoseconds.");

        let time = Utc.with_ymd_and_hms(2025, 4, 30, 21, 41, 28).unwrap()
            + Duration::from_nanos(271_330_430);

        assert_eq!(expected.seconds, 0xebbd1788u32);
        assert_eq!(expected.fractions, 0x4575e93fu32);

        // Just for good measure.
        do_test_simple_ntp_conversion_roundtrip(expected.clone(), time);

        let re_raw_data = Into::<Vec<u8>>::into(expected);

        assert!(raw_data[0..4].eq(&re_raw_data[0..4]));
        assert!(raw_data[4..8].eq(&re_raw_data[4..8]));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Z {
    Ntp,
    Ptp,
}

impl Display for Z {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Z::Ntp => write!(f, "Ntp"),
            Z::Ptp => write!(f, "Ptp"),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ErrorEstimate {
    pub scale: u8,
    pub multiple: u8,
    pub synchronized: bool,
    pub z: Z,
}

impl Debug for ErrorEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErrorEstimate")
            .field("scale", &self.scale)
            .field("multiple", &self.multiple)
            .field("synchronized", &self.synchronized)
            .field("protocol", &self.z)
            .field("estimate", &format_args!("{}ns", self.error()))
            .finish()
    }
}

impl ErrorEstimate {
    #[allow(non_upper_case_globals)]
    pub const RawSize: usize = 2;

    pub fn error(&self) -> u64 {
        ((self.multiple as u64 * NANOSECONDS_PER_SECOND) << self.scale) >> 32
    }
}

impl Default for ErrorEstimate {
    fn default() -> Self {
        Self {
            scale: 0,
            multiple: 1,
            synchronized: false,
            z: Z::Ntp,
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
        } else {
            Ok(Self {
                synchronized: value[0] & 0x80 != 0,
                scale: value[0] & 0x3f,
                multiple: value[1],
                z: if value[0] & 0x40 == 0 { Z::Ntp } else { Z::Ptp },
            })
        }
    }
}

impl From<&ErrorEstimate> for Vec<u8> {
    fn from(value: &ErrorEstimate) -> Self {
        let mut result = vec![0u8; 2];
        result[0] = if value.synchronized { 0x80 } else { 0x00 };
        result[0] |= if value.z == Z::Ptp { 0x40 } else { 0x00 };
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

pub enum TimeSource {
    HWAssist,
    SWLocal,
    ControlPlane,
    Reserved,
}

impl From<TimeSource> for u8 {
    fn from(value: TimeSource) -> u8 {
        match value {
            TimeSource::Reserved => 0u8,
            TimeSource::HWAssist => 1u8,
            TimeSource::SWLocal => 2u8,
            TimeSource::ControlPlane => 3u8,
        }
    }
}

#[cfg(test)]
mod error_estimate_test {
    use std::time::Duration;

    use super::ErrorEstimate;
    use super::Z;

    #[test]
    pub fn test_serialization_ntp() {
        let ee = ErrorEstimate {
            synchronized: true,
            scale: 0x5,
            multiple: 0x12,
            z: Z::Ntp,
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
        if serialized_ee[0] & 0x40 != 0 {
            panic!("Did not serialize the z value correctly");
        }
    }

    #[test]
    pub fn test_serialization_ptp() {
        let ee = ErrorEstimate {
            synchronized: true,
            scale: 0x5,
            multiple: 0x12,
            z: Z::Ptp,
        };

        let serialized_ee = Into::<Vec<u8>>::into(ee);

        if serialized_ee[0] & 0x80 == 0x0 {
            panic!("Did not serialize the synchronized flag correctly");
        }
        if serialized_ee[0] & 0x3f != 0x5 {
            panic!("Did not serialize the scale value correctly");
        }
        if serialized_ee[1] != 0x12 {
            panic!("Did not serialize the multiply value correctly");
        }
        if serialized_ee[0] & 0x40 == 0 {
            panic!("Did not serialize the z value correctly");
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
        assert_eq!(parsed_ee.z, Z::Ntp);
    }

    #[test]
    pub fn test_deserialization_ntp() {
        let raw_ee = [0x85u8, 0x12u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_err() {
            panic!("Should have been able to parse the raw bytes into a valid error estimate.")
        }
        let parsed_ee = parsed_ee.unwrap();
        assert_eq!(parsed_ee.z, Z::Ntp);
    }

    #[test]
    pub fn test_deserialization_ptp() {
        let raw_ee = [0xC5u8, 0x12u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_err() {
            panic!("Should have been able to parse the raw bytes into a valid error estimate.")
        }

        let parsed_ee = parsed_ee.unwrap();
        assert_eq!(parsed_ee.z, Z::Ptp);
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
    pub fn test_display_ptp() {
        let raw_ee = [0xC5u8, 0x12u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_err() {
            panic!("Should have been able to parse the raw bytes into a valid error estimate.")
        }

        let parsed_ee = parsed_ee.unwrap();

        assert!(format!("{parsed_ee:?}").contains("Ptp"))
    }

    #[test]
    pub fn test_display_ntp() {
        let raw_ee = [0x85u8, 0x12u8];
        let parsed_ee = TryInto::<ErrorEstimate>::try_into(raw_ee.as_slice());

        if parsed_ee.is_err() {
            panic!("Should have been able to parse the raw bytes into a valid error estimate.")
        }

        let parsed_ee = parsed_ee.unwrap();

        assert!(format!("{parsed_ee:?}").contains("Ntp"))
    }

    #[test]
    pub fn test_error_estimate_calculation() {
        // Check: 1 second.
        let ee = ErrorEstimate {
            scale: 32,
            multiple: 1,
            synchronized: false,
            z: Z::Ntp,
        };
        let ms = Duration::from_nanos(ee.error()).as_secs();
        assert_eq!(ms, 1);

        // Check: 1/2 second.
        let ee = ErrorEstimate {
            scale: 31,
            multiple: 1,
            synchronized: false,
            z: Z::Ntp,
        };
        let ms = Duration::from_nanos(ee.error()).as_nanos();
        assert_eq!(ms, 500000000);
    }
}
