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

use std::fmt::{Debug, Display};
use std::vec;

use etherparse::Ethernet2Header;
use nix::sys::socket::Ipv6ExtHeader;
use slog::Logger;

use crate::connection_generator::IpHeaders;
use crate::os::MacAddr;
use crate::stamp::StampError;

use crate::ip::{DscpValue, EcnValue};

#[derive(Clone)]
pub enum TestArgument {
    Ttl(u8),
    Ecn(EcnValue),
    Dscp(DscpValue),
    PeerMacAddress(MacAddr),
    HeaderOption(Ipv6ExtHeader),
    Invalid,
}

impl Default for TestArgument {
    fn default() -> Self {
        Self::Invalid
    }
}

impl From<TestArgument> for Ipv6ExtHeader {
    fn from(value: TestArgument) -> Ipv6ExtHeader {
        match value {
            TestArgument::HeaderOption(header) => header,
            _ => {
                panic!("Should not ask to convert a TTL, ECN or DSCP Test Argument into an IPv6ExtHeader.")
            }
        }
    }
}

impl From<TestArgument> for Vec<u8> {
    fn from(value: TestArgument) -> Vec<u8> {
        match value {
            TestArgument::Ttl(_) | TestArgument::Ecn(_) | TestArgument::Dscp(_) => {
                panic!("Should not ask to convert a TTL, ECN or DSCP Test Argument into a vector of bytes.")
            }
            TestArgument::PeerMacAddress(v) => v.mac.to_vec(),
            TestArgument::HeaderOption(header) => header.header_body,
            TestArgument::Invalid => vec![],
        }
    }
}

impl From<TestArgument> for u8 {
    fn from(value: TestArgument) -> u8 {
        match value {
            TestArgument::Ttl(ttl) => ttl,
            TestArgument::Ecn(ecn) => Into::<u8>::into(ecn),
            TestArgument::Dscp(value) => Into::<u8>::into(value),
            TestArgument::PeerMacAddress(_) | TestArgument::HeaderOption(_) => {
                panic!("Should not ask to convert a Peer MAC Address or Header Option Argument into a byte.")
            }
            TestArgument::Invalid => -1i32 as u8,
        }
    }
}

impl Display for TestArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestArgument::Ttl(ttl) => write!(f, "TTL = {ttl}"),
            TestArgument::Ecn(ecn) => write!(f, "ECN = {ecn:?}"),
            TestArgument::Dscp(value) => write!(f, "Dscp = {value:?}"),
            TestArgument::PeerMacAddress(value) => write!(f, "Peer Mac Address = {value:?}"),
            TestArgument::HeaderOption(header) => write!(f, "Header option = {header:x?}"),
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
    HeaderOption = 4,
    MaxParameterKind = 5,
}

#[derive(Clone, Debug, Default)]
pub struct TestArguments {
    arguments: Vec<(TestArgumentKind, TestArgument)>,
}

impl TestArguments {
    pub fn get_parameter_value<T: From<TestArgument>>(
        &self,
        parameter: TestArgumentKind,
    ) -> Result<Vec<T>, StampError> {
        let result: Vec<_> = self
            .arguments
            .iter()
            .filter_map(|v| {
                if v.0 == parameter {
                    Some(v.1.clone())
                } else {
                    None
                }
            })
            .map(Into::<T>::into)
            .collect();
        if !result.is_empty() {
            Ok(result)
        } else {
            Err(StampError::MissingRequiredArgument(parameter))
        }
    }

    pub fn add_argument<T: Into<TestArgument>>(&mut self, parameter: TestArgumentKind, arg: T) {
        self.arguments
            .push((parameter, Into::<TestArgument>::into(arg)));
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
static HEADER_OPTION_TEST_PARAMETER: HeaderOptionTestParameter = HeaderOptionTestParameter {};

impl TestParameters {
    pub fn new() -> Self {
        Self {
            parameters: vec![
                &TTL_TEST_PARAMETER,
                &ECN_TEST_PARAMETER,
                &DSCP_TEST_PARAMETER,
                &PEER_MAC_ADDRESS_TEST_PARAMETER,
                &HEADER_OPTION_TEST_PARAMETER,
            ],
        }
    }

    pub fn get_arguments(
        &self,
        ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        logger: Logger,
    ) -> Result<TestArguments, StampError> {
        let mut arguments: Vec<(TestArgumentKind, TestArgument)> = vec![];

        self.parameters
            .iter()
            .filter_map(|param| {
                param
                    .argument_from(ethernet_hdr, ip_hdr, logger.clone())
                    .map(|argument| (param.argument_kind(), argument))
            })
            .for_each(|(kind, value)| {
                for arg in value {
                    arguments.push((kind, arg));
                }
            });
        Ok(TestArguments { arguments })
    }
}

trait TestParameter {
    fn argument_kind(&self) -> TestArgumentKind;
    fn argument_from(
        &self,
        ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        logger: Logger,
    ) -> Option<Vec<TestArgument>>;
}

pub struct PeerMACAddressTestParameter {}

impl TestParameter for PeerMACAddressTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::PeerMacAddress
    }

    fn argument_from(
        &self,
        ethernet_hdr: &Ethernet2Header,
        _ip_hdr: &IpHeaders,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        Some(vec![TestArgument::PeerMacAddress(MacAddr {
            mac: ethernet_hdr.source,
        })])
    }
}

pub struct TtlTestParameter {}

impl TestParameter for TtlTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ttl
    }

    fn argument_from(
        &self,
        _ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        match ip_hdr {
            IpHeaders::Left(ipv4) => Some(vec![TestArgument::Ttl(ipv4.time_to_live)]),
            IpHeaders::Right(ipv6) => Some(vec![TestArgument::Ttl(ipv6.0.hop_limit)]),
        }
    }
}

pub struct EcnTestParameter {}

impl TestParameter for EcnTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ecn
    }

    fn argument_from(
        &self,
        _ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        match ip_hdr {
            IpHeaders::Left(ipv4) => Some(vec![TestArgument::Ecn(ipv4.ecn.into())]),
            IpHeaders::Right(ipv6) => {
                Some(vec![TestArgument::Ecn((ipv6.0.traffic_class & 0x3).into())])
            }
        }
    }
}

pub struct DscpTestParameter {}

impl TestParameter for DscpTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Dscp
    }

    fn argument_from(
        &self,
        _ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        //Some(TestArgument::Dscp(ip_hdr.dscp))
        match ip_hdr {
            // No need to shift right here because ipv4.dscp is _not_ a raw value (See TryInto<DscpValue> for Ipv4Dscp)
            IpHeaders::Left(ipv4) => TryInto::<DscpValue>::try_into(ipv4.dscp)
                .map(TestArgument::Dscp)
                .map(|v| Some(vec![v]))
                .unwrap_or(None),
            // Need to shift right here because the value extracted from traffic class is raw (and try_into expects shifting!)
            IpHeaders::Right(ipv6) => TryInto::<DscpValue>::try_into(ipv6.0.traffic_class >> 2)
                .map(TestArgument::Dscp)
                .map(|v| Some(vec![v]))
                .unwrap_or(None),
        }
    }
}

pub struct HeaderOptionTestParameter {}

impl TestParameter for HeaderOptionTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::HeaderOption
    }

    fn argument_from(
        &self,
        _ethernet_hdr: &Ethernet2Header,
        ip_hdr: &IpHeaders,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        //Some(TestArgument::Dscp(ip_hdr.dscp))
        match ip_hdr {
            IpHeaders::Left(_) => None,
            IpHeaders::Right(ipv6) => Some(
                ipv6.1
                    .iter()
                    .map(|v| TestArgument::HeaderOption(v.clone()))
                    .collect(),
            ),
        }
    }
}
