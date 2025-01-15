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

use std::fmt::{Debug, Display};
use std::vec;

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use slog::Logger;

use crate::os::MacAddr;
use crate::stamp::StampError;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum EcnValue {
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

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DscpValue {
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
    Invalid,
}

impl From<DscpValue> for u8 {
    fn from(value: DscpValue) -> Self {
        (value as u8) << 2
    }
}

impl From<u8> for DscpValue {
    fn from(value: u8) -> Self {
        // NOTE: We expect that the given value to convert
        // is _already_ shifted to the right!
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
            _ => DscpValue::Invalid,
        }
    }
}

#[derive(Clone, Copy)]
pub enum TestArgument {
    Ttl(u8),
    Ecn(EcnValue),
    Dscp(DscpValue),
    PeerMacAddress(MacAddr),
    Invalid,
}

impl Default for TestArgument {
    fn default() -> Self {
        Self::Invalid
    }
}

impl From<TestArgument> for Vec<u8> {
    fn from(value: TestArgument) -> Vec<u8> {
        match value {
            TestArgument::Ttl(_) | TestArgument::Ecn(_) | TestArgument::Dscp(_) => {
                panic!("Should not ask to convert a Peer MAC Address Argument into two bytes.")
            }
            TestArgument::PeerMacAddress(v) => v.mac.to_vec(),
            TestArgument::Invalid => vec![],
        }
    }
}

impl From<TestArgument> for u16 {
    fn from(value: TestArgument) -> u16 {
        match value {
            TestArgument::Ttl(ttl) => ttl as u16,
            TestArgument::Ecn(ecn) => ecn as u16,
            TestArgument::Dscp(value) => value as u16,
            TestArgument::PeerMacAddress(_) => {
                panic!("Should not ask to convert a Peer MAC Address Argument into two bytes.")
            }
            TestArgument::Invalid => -1i32 as u16,
        }
    }
}

impl From<TestArgument> for u8 {
    fn from(value: TestArgument) -> u8 {
        match value {
            TestArgument::Ttl(ttl) => ttl,
            TestArgument::Ecn(ecn) => ecn as u8,
            TestArgument::Dscp(value) => Into::<u8>::into(value),
            TestArgument::PeerMacAddress(_) => {
                panic!("Should not ask to convert a Peer MAC Address Argument into a byte.")
            }
            TestArgument::Invalid => -1i32 as u8,
        }
    }
}

impl Display for TestArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestArgument::Ttl(ttl) => write!(f, "TTL = {}", ttl),
            TestArgument::Ecn(ecn) => write!(f, "ECN = {:?}", ecn),
            TestArgument::Dscp(value) => write!(f, "Dscp = {:?}", value),
            TestArgument::PeerMacAddress(value) => write!(f, "Peer Mac Address = {:?}", value),
            TestArgument::Invalid => write!(f, "Invalid."),
        }
    }
}

impl Debug for TestArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(PartialEq, PartialOrd, Debug, Clone, Copy)]
#[repr(usize)]
pub enum TestArgumentKind {
    Ttl = 0,
    Ecn = 1,
    Dscp = 2,
    PeerMacAddress = 3,
    MaxParameterKind = 4,
}

#[derive(Clone, Debug)]
pub struct TestArguments {
    arguments: Vec<TestArgument>,
}

impl TestArguments {
    pub fn empty_arguments() -> Self {
        TestArguments {
            arguments: [TestArgument::Invalid; TestArgumentKind::MaxParameterKind as usize]
                .to_vec(),
        }
    }
}

impl TestArguments {
    pub fn get_parameter_value<T: From<TestArgument>>(
        &self,
        parameter: TestArgumentKind,
    ) -> Result<T, StampError> {
        if parameter < TestArgumentKind::MaxParameterKind {
            match self.arguments[parameter as usize] {
                TestArgument::Invalid => Err(StampError::MissingRequiredArgument(parameter)),
                e => Ok(Into::<T>::into(e)),
            }
        } else {
            Err(StampError::MissingRequiredArgument(parameter))
        }
    }

    pub fn add_argument<T: Into<TestArgument>>(&mut self, parameter: TestArgumentKind, arg: T) {
        if parameter < TestArgumentKind::MaxParameterKind {
            self.arguments[parameter as usize] = Into::<TestArgument>::into(arg);
        }
    }
}

#[derive(Clone)]
pub struct TestParameters {
    parameters: Vec<&'static dyn TestParameter>,
}

static TTL_TEST_PARAMETER: TtlTestParameter = TtlTestParameter {};
static ECN_TEST_PARAMETER: EcnTestParameter = EcnTestParameter {};
static DSCP_TEST_PARAMETER: DscpTestParameter = DscpTestParameter {};
static PEER_MAC_ADDRESS_TEST_PARAMETER: PeerMACAddressTestParameter =
    PeerMACAddressTestParameter {};

impl TestParameters {
    pub fn new() -> Self {
        Self {
            parameters: vec![
                &TTL_TEST_PARAMETER,
                &ECN_TEST_PARAMETER,
                &DSCP_TEST_PARAMETER,
                &PEER_MAC_ADDRESS_TEST_PARAMETER,
            ],
        }
    }

    pub fn get_arguments(
        &self,
        ethernet_pkt: &EthernetPacket,
        ip_pkt: &Ipv4Packet,
        logger: Logger,
    ) -> Result<TestArguments, StampError> {
        let mut arguments =
            vec![TestArgument::Invalid; TestArgumentKind::MaxParameterKind as usize];

        self.parameters
            .iter()
            .filter_map(|param| {
                param
                    .argument_from(ethernet_pkt, ip_pkt, logger.clone())
                    .map(|argument| (param.argument_kind(), argument))
            })
            .for_each(|(kind, value)| {
                arguments[kind as usize] = value;
            });
        Ok(TestArguments { arguments })
    }
}

trait TestParameter {
    fn argument_kind(&self) -> TestArgumentKind;
    fn argument_from(
        &self,
        ethernet_pkt: &EthernetPacket,
        ip_hdr: &Ipv4Packet,
        logger: Logger,
    ) -> Option<TestArgument>;
}

pub struct PeerMACAddressTestParameter {}

impl TestParameter for PeerMACAddressTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::PeerMacAddress
    }

    fn argument_from(
        &self,
        ethernet_pkt: &EthernetPacket,
        _ip_hdr: &Ipv4Packet,
        _logger: Logger,
    ) -> Option<TestArgument> {
        Some(TestArgument::PeerMacAddress(
            ethernet_pkt.get_source().into(),
        ))
    }
}

pub struct TtlTestParameter {}

impl TestParameter for TtlTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ttl
    }

    fn argument_from(
        &self,
        _ethernet_pkt: &EthernetPacket,
        ip_hdr: &Ipv4Packet,
        _logger: Logger,
    ) -> Option<TestArgument> {
        Some(TestArgument::Ttl(ip_hdr.get_ttl()))
    }
}

pub struct EcnTestParameter {}

impl TestParameter for EcnTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ecn
    }

    fn argument_from(
        &self,
        _ethernet_pkt: &EthernetPacket,
        ip_hdr: &Ipv4Packet,
        _logger: Logger,
    ) -> Option<TestArgument> {
        Some(TestArgument::Ecn(ip_hdr.get_ecn().into()))
    }
}

pub struct DscpTestParameter {}

impl TestParameter for DscpTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Dscp
    }

    fn argument_from(
        &self,
        _ethernet_pkt: &EthernetPacket,
        ip_hdr: &Ipv4Packet,
        _logger: Logger,
    ) -> Option<TestArgument> {
        Some(TestArgument::Dscp(ip_hdr.get_dscp().into()))
    }
}
