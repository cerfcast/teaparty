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
use std::net::UdpSocket;
use std::{mem, vec};

use nix::libc;
use nix::sys::socket::sockopt::{IpRecvTos, Ipv4RecvTtl};
use nix::sys::socket::{ControlMessageOwned, SetSockOpt};
use slog::Logger;
use slog::{error, info};

use crate::stamp::StampError;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum EcnValue {
    NotEct = 0x0u8,
    Ect1 = 0x1u8,
    Ect0 = 0x2u8,
    Ce = 0x3u8,
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
    fn from(mut value: u8) -> Self {
        value >>= 2;
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
    Invalid,
}

impl Default for TestArgument {
    fn default() -> Self {
        Self::Invalid
    }
}

impl From<TestArgument> for u16 {
    fn from(value: TestArgument) -> u16 {
        match value {
            TestArgument::Ttl(ttl) => ttl as u16,
            TestArgument::Ecn(ecn) => ecn as u16,
            TestArgument::Dscp(value) => value as u16,
            TestArgument::Invalid => -1i32 as u16,
        }
    }
}

impl From<TestArgument> for u8 {
    fn from(value: TestArgument) -> u8 {
        match value {
            TestArgument::Ttl(ttl) => ttl,
            TestArgument::Ecn(ecn) => ecn as u8,
            TestArgument::Dscp(value) => value as u8,
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
    MaxParameterKind = 3,
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

impl TestParameters {
    pub fn new() -> Self {
        Self {
            parameters: vec![
                &TTL_TEST_PARAMETER,
                &ECN_TEST_PARAMETER,
                &DSCP_TEST_PARAMETER,
            ],
        }
    }

    pub fn configure_parameters(
        &mut self,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<usize, StampError> {
        let mut space = 0usize;
        for parameter in &mut self.parameters {
            space += parameter.configure_server(socket, logger.clone())?;
        }
        Ok(space)
    }

    pub fn get_arguments(
        &self,
        cmsgs: Vec<ControlMessageOwned>,
        logger: Logger,
    ) -> Result<TestArguments, StampError> {
        let mut arguments =
            vec![TestArgument::Invalid; TestArgumentKind::MaxParameterKind as usize];

        for cmsg in cmsgs.iter() {
            self.parameters
                .iter()
                .filter_map(|param| {
                    param
                        .argument_from(cmsg, logger.clone())
                        .map(|argument| (param.argument_kind(), argument))
                })
                .for_each(|(kind, value)| {
                    arguments[kind as usize] = value;
                });
        }
        Ok(TestArguments { arguments })
    }
}

trait TestParameter {
    fn argument_kind(&self) -> TestArgumentKind;
    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError>;
    fn argument_from(&self, cmsg: &ControlMessageOwned, logger: Logger) -> Option<TestArgument>;
}

pub struct TtlTestParameter {}

impl TestParameter for TtlTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ttl
    }

    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError> {
        let recv_ttl_value = true;
        Ipv4RecvTtl.set(&socket, &recv_ttl_value).map_err(|e| {
            error!(
                logger,
                "There was an error configuring the server socket for the Ttl test parameter: {}",
                e
            );
            Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            ))
        })?;
        unsafe { Ok(libc::CMSG_SPACE(mem::size_of::<u8>() as libc::c_uint) as usize) }
    }

    fn argument_from(&self, cmsg: &ControlMessageOwned, logger: Logger) -> Option<TestArgument> {
        match cmsg {
            ControlMessageOwned::Ipv4Ttl(v) => Some(TestArgument::Ttl(*v as u8)),
            _ => {
                info!(
                    logger,
                    "{:?} does not appear to be an argument for the Ttl test parameter.", cmsg
                );
                None
            }
        }
    }
}

pub struct EcnTestParameter {}

impl TestParameter for EcnTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Ecn
    }

    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError> {
        let recv_tos_value = true;
        IpRecvTos.set(&socket, &recv_tos_value).map_err(|e| {
            error!(
                logger,
                "There was an error configuring the server socket for the Ecn test parameter: {}",
                e
            );
            Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            ))
        })?;
        unsafe { Ok(libc::CMSG_SPACE(mem::size_of::<u8>() as libc::c_uint) as usize) }
    }

    fn argument_from(&self, cmsg: &ControlMessageOwned, logger: Logger) -> Option<TestArgument> {
        match cmsg {
            ControlMessageOwned::Ipv4Tos(v) => Some(TestArgument::Ecn((*v).into())),
            _ => {
                info!(
                    logger,
                    "{:?} does not appear to be an argument for the Ecn test parameter.", cmsg
                );
                None
            }
        }
    }
}

pub struct DscpTestParameter {}

impl TestParameter for DscpTestParameter {
    fn argument_kind(&self) -> TestArgumentKind {
        TestArgumentKind::Dscp
    }

    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError> {
        let recv_tos_value = true;
        IpRecvTos.set(&socket, &recv_tos_value).map_err(|e| {
            error!(
                logger,
                "There was an error configuring the server socket for the Dscp test parameter: {}",
                e
            );
            Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            ))
        })?;
        unsafe { Ok(libc::CMSG_SPACE(mem::size_of::<u8>() as libc::c_uint) as usize) }
    }

    fn argument_from(&self, cmsg: &ControlMessageOwned, logger: Logger) -> Option<TestArgument> {
        match cmsg {
            ControlMessageOwned::Ipv4Tos(v) => Some(TestArgument::Dscp((v & 0xfc).into())),
            _ => {
                info!(
                    logger,
                    "{:?} does not appear to be an argument for the Dscp test parameter.", cmsg
                );
                None
            }
        }
    }
}
