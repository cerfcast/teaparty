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

use std::fmt::Debug;

use clap::ValueEnum;

#[repr(u8)]
#[derive(Default, Clone, Copy, Debug, ValueEnum, PartialEq, Eq, PartialOrd)]
pub enum EcnValue {
    #[default]
    NotEct = 0x0u8,
    Ect1 = 0x1u8,
    Ect0 = 0x2u8,
    Ce = 0x3u8,
}

impl From<EcnValue> for u8 {
    fn from(value: EcnValue) -> Self {
        value as u8
    }
}

impl From<u8> for EcnValue {
    fn from(value: u8) -> Self {
        let result = [
            EcnValue::NotEct,
            EcnValue::Ect1,
            EcnValue::Ect0,
            EcnValue::Ce,
        ];
        result[(value & 0x3) as usize]
    }
}

impl From<etherparse::Ipv4Ecn> for EcnValue {
    fn from(value: etherparse::Ipv4Ecn) -> Self {
        match value {
            etherparse::Ipv4Ecn::ZERO => Self::NotEct,
            etherparse::Ipv4Ecn::ONE => Self::Ect1,
            etherparse::Ipv4Ecn::TWO => Self::Ect0,
            etherparse::Ipv4Ecn::TRHEE => Self::Ce,
            _ => unreachable!(),
        }
    }
}

#[repr(u8)]
#[derive(Default, Clone, Copy, Debug, ValueEnum)]
pub enum DscpValue {
    #[default]
    CS0 = 0,
    CS1 = 8,
    CS2 = 16,
    CS3 = 24,
    CS4 = 32,
    CS5 = 40,
    CS6 = 48,
    CS7 = 56,
    AF11 = 10,
    AF12 = 12,
    AF13 = 14,
    AF21 = 18,
    AF22 = 20,
    AF23 = 22,
    AF31 = 26,
    AF32 = 28,
    AF33 = 30,
    AF41 = 34,
    AF42 = 36,
    AF43 = 38,
    EF = 46,
    #[allow(clippy::upper_case_acronyms)]
    VOICEADMIT = 44,
    #[value(skip)]
    Invalid,
}

impl From<DscpValue> for u8 {
    // The resulting value will already be shifted into the upper two bits.
    fn from(value: DscpValue) -> Self {
        (value as u8) << 2
    }
}

impl From<u8> for DscpValue {
    fn from(value: u8) -> Self {
        // NOTE: We expect that the given value to convert
        // is _already_ shifted to the right!
        if 0xc0 & value != 0 {
            return DscpValue::Invalid;
        }
        match value {
            0 => DscpValue::CS0,
            8 => DscpValue::CS1,
            16 => DscpValue::CS2,
            24 => DscpValue::CS3,
            32 => DscpValue::CS4,
            40 => DscpValue::CS5,
            48 => DscpValue::CS6,
            56 => DscpValue::CS7,
            10 => DscpValue::AF11,
            12 => DscpValue::AF12,
            14 => DscpValue::AF13,
            18 => DscpValue::AF21,
            20 => DscpValue::AF22,
            22 => DscpValue::AF23,
            26 => DscpValue::AF31,
            28 => DscpValue::AF32,
            30 => DscpValue::AF33,
            34 => DscpValue::AF41,
            36 => DscpValue::AF42,
            38 => DscpValue::AF43,
            46 => DscpValue::EF,
            44 => DscpValue::VOICEADMIT,
            _ => unreachable!()
        }
    }
}

impl From<etherparse::Ipv4Dscp> for DscpValue {
    fn from(value: etherparse::Ipv4Dscp) -> Self {
        Into::<Self>::into(value.value())
    }
}

#[cfg(test)]
mod test_dscp_conversions {
    use etherparse::Ipv4Dscp;

    use crate::ip::DscpValue;

    #[test]
    fn test_dscp_from_raw_to_dscp_value() {
        assert!(matches!(Into::<DscpValue>::into(56), DscpValue::CS7))
    }

    #[test]
    fn test_dscp_from_dscp_value_to_raw() {
        assert!(Into::<u8>::into(DscpValue::AF11) == 10 << 2);
    }

    #[test]
    fn test_dscp_from_dscp_value_to_raw_2() {
        assert!(Into::<u8>::into(DscpValue::AF33) == 30 << 2);
    }

    #[test]
    fn test_dscp_raw_roundtrip() {
        let res = Into::<u8>::into(DscpValue::AF33);
        assert!(res == 30 << 2);
        assert!(matches!(Into::<DscpValue>::into(res >> 2), DscpValue::AF33));
    }

    #[test]
    fn test_dscp_raw_roundtrip_fail() {
        let res = Into::<u8>::into(DscpValue::AF33);
        assert!(res == 30 << 2);
        // Testing here that an unshifted value will fail.
        assert!(!matches!(Into::<DscpValue>::into(res), DscpValue::AF33));
    }

    #[test]
    fn test_dscp_from_etherparse_to_raw() {
        let value = unsafe { Ipv4Dscp::new_unchecked(36) };
        assert!(value.value() == 36)
    }

    #[test]
    fn test_dscp_from_etherparse_to_dscp_value() {
        let value = unsafe { Ipv4Dscp::new_unchecked(28) };
        assert!(matches!(Into::<DscpValue>::into(value), DscpValue::AF32))
    }

    #[test]
    fn test_dscp_upper_bits_filled_error() {
        let value = 0xff;
        assert!(matches!(Into::<DscpValue>::into(value), DscpValue::Invalid))
    }
}

#[cfg(test)]
mod test_ecn_conversions {
    use etherparse::Ipv4Ecn;

    use crate::ip::EcnValue;

    #[test]
    fn test_ecn_from_raw_to_ecn_value_ect1() {
        assert!(matches!(Into::<EcnValue>::into(1), EcnValue::Ect1))
    }
    #[test]
    fn test_ecn_from_raw_to_ecn_value_ect2() {
        assert!(matches!(Into::<EcnValue>::into(2), EcnValue::Ect0))
    }

    #[test]
    fn test_ecn_from_ecn_value_ect1_to_raw() {
        assert!(Into::<u8>::into(EcnValue::Ect1) == 1);
    }
    #[test]
    fn test_ecn_from_ecn_value_ect0_to_raw() {
        assert!(Into::<u8>::into(EcnValue::Ect0) == 2);
    }

    #[test]
    fn test_ecn_from_etherparse_to_ecn_value() {
        let value = Ipv4Ecn::ONE;
        assert!(matches!(Into::<EcnValue>::into(value), EcnValue::Ect1));
    }

    #[test]
    fn test_ecn_from_etherparse_to_ecn_value2() {
        let value = Ipv4Ecn::TWO;
        assert!(matches!(Into::<EcnValue>::into(value), EcnValue::Ect0));
    }

    #[test]
    fn test_ecn_from_etherparse_to_raw() {
        let value = Ipv4Ecn::ONE;
        assert!(value.value() == 1);
        assert!(Into::<u8>::into(value) == 1);
    }

    #[test]
    fn test_ecn_from_etherparse_to_raw2() {
        let value = Ipv4Ecn::TWO;
        assert!(value.value() == 2);
        assert!(Into::<u8>::into(value) == 2);
    }

    #[test]
    fn test_ecn_from_etherparse_to_raw3() {
        let value = Ipv4Ecn::TRHEE;
        assert!(value.value() == 3);
        assert!(Into::<u8>::into(value) == 3);
    }
}
