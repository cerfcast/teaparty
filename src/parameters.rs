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
use slog::Logger;

use crate::connection_generator::{IpVersion, NetworkOptions};
use crate::os::MacAddr;
use crate::stamp::StampError;

use crate::ip::{DscpValue, EcnValue, ExtensionHeader};

#[derive(Clone)]
pub enum TestArgument {
    Ttl(u8),
    RawIpHdr(Vec<u8>),
    Ecn(EcnValue),
    Dscp(DscpValue),
    PeerMacAddress(MacAddr),
    HeaderOption(ExtensionHeader),
    Invalid,
}

impl Default for TestArgument {
    fn default() -> Self {
        Self::Invalid
    }
}

impl From<TestArgument> for ExtensionHeader {
    fn from(value: TestArgument) -> ExtensionHeader {
        match value {
            TestArgument::HeaderOption(header) => header,
            _ => {
                panic!("Should not ask to convert a TTL, RawIPHdr, ECN or DSCP Test Argument into an IPv6ExtHeader.")
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
            TestArgument::HeaderOption(header) => header.into(),
            TestArgument::RawIpHdr(bytes) => bytes,
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
            TestArgument::PeerMacAddress(_)
            | TestArgument::RawIpHdr(_)
            | TestArgument::HeaderOption(_) => {
                panic!("Should not ask to convert a Peer MAC Address, Raw IP Hdr or Header Option Argument into a byte.")
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
            TestArgument::RawIpHdr(header) => write!(f, "Raw IP Header = {header:x?}"),
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
    RawIpHdr = 1,
    Ecn = 2,
    Dscp = 3,
    PeerMacAddress = 4,
    HeaderOption = 5,
    MaxParameterKind = 6,
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
static RAW_IPHDR_TEST_PARAMETER: RawIpHdrTestParameter = RawIpHdrTestParameter {};
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
                &RAW_IPHDR_TEST_PARAMETER,
                &ECN_TEST_PARAMETER,
                &DSCP_TEST_PARAMETER,
                &PEER_MAC_ADDRESS_TEST_PARAMETER,
                &HEADER_OPTION_TEST_PARAMETER,
            ],
        }
    }

    pub fn get_arguments(
        &self,
        raw_ip_hdr: Vec<u8>,
        ethernet_hdr: &Ethernet2Header,
        network_options: &NetworkOptions,
        logger: Logger,
    ) -> Result<TestArguments, StampError> {
        let mut arguments: Vec<(TestArgumentKind, TestArgument)> = vec![];

        self.parameters
            .iter()
            .filter_map(|param| {
                param
                    .argument_from(&raw_ip_hdr, ethernet_hdr, network_options, logger.clone())
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
        raw_ip_hdr: &[u8],
        ethernet_hdr: &Ethernet2Header,
        network_options: &NetworkOptions,
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
        _raw_ip_hdr: &[u8],
        ethernet_hdr: &Ethernet2Header,
        _network_options: &NetworkOptions,
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
        _raw_ip_hdr: &[u8],
        _ethernet_hdr: &Ethernet2Header,
        network_options: &NetworkOptions,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        Some(vec![TestArgument::Ttl(network_options.ttl)])
    }
}

pub struct RawIpHdrTestParameter {}

impl TestParameter for RawIpHdrTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::RawIpHdr
    }

    fn argument_from(
        &self,
        raw_ip_hdr: &[u8],
        _ethernet_hdr: &Ethernet2Header,
        _network_options: &NetworkOptions,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        if !raw_ip_hdr.is_empty() {
            Some(vec![TestArgument::RawIpHdr(raw_ip_hdr.to_vec())])
        } else {
            None
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
        _raw_ip_hdr: &[u8],
        _ethernet_hdr: &Ethernet2Header,
        ip_hdr: &NetworkOptions,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        Some(vec![TestArgument::Ecn(ip_hdr.ecn)])
    }
}

pub struct DscpTestParameter {}

impl TestParameter for DscpTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Dscp
    }

    fn argument_from(
        &self,
        _raw_ip_hdr: &[u8],
        _ethernet_hdr: &Ethernet2Header,
        network_options: &NetworkOptions,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        Some(vec![TestArgument::Dscp(network_options.dscp)])
    }
}

pub struct HeaderOptionTestParameter {}

impl TestParameter for HeaderOptionTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::HeaderOption
    }

    fn argument_from(
        &self,
        _raw_ip_hdr: &[u8],
        _ethernet_hdr: &Ethernet2Header,
        network_options: &NetworkOptions,
        _logger: Logger,
    ) -> Option<Vec<TestArgument>> {
        match network_options.mode {
            IpVersion::Four => None,
            IpVersion::Six => Some(
                network_options
                    .extension_headers
                    .as_ref()?
                    .iter()
                    .map(|v| TestArgument::HeaderOption(v.clone()))
                    .collect(),
            ),
        }
    }
}
