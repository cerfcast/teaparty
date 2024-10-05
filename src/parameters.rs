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

use nix::sys::socket::sockopt::{IpRecvTos, Ipv4RecvTtl};
use nix::sys::socket::{ControlMessageOwned, SetSockOpt};
use nix::{cmsg_space, libc};
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

impl From<&u8> for EcnValue {
    fn from(value: &u8) -> Self {
        let result = [
            EcnValue::NotEct,
            EcnValue::Ect0,
            EcnValue::Ect1,
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
}

impl From<&u8> for DscpValue {
    fn from(value: &u8) -> Self {
        let result = [
            DscpValue::CS0,
            DscpValue::CS1,
            DscpValue::CS2,
            DscpValue::CS3,
            DscpValue::CS4,
            DscpValue::CS5,
            DscpValue::CS6,
            DscpValue::CS7,
            DscpValue::AF11,
            DscpValue::AF12,
            DscpValue::AF13,
            DscpValue::AF21,
            DscpValue::AF22,
            DscpValue::AF23,
            DscpValue::AF31,
            DscpValue::AF32,
            DscpValue::AF33,
            DscpValue::AF41,
            DscpValue::AF42,
            DscpValue::AF43,
            DscpValue::EF,
            DscpValue::VOICEADMIT,
        ];
        result[(value >> 2) as usize]
    }
}

#[derive(Clone)]
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

#[derive(PartialEq, PartialOrd)]
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
        TestArguments { arguments: vec![] }
    }
}

impl TestArguments {
    pub fn get_parameter_value<T: From<TestArgument>>(self, parameter: TestArgumentKind) -> T {
        if parameter < TestArgumentKind::MaxParameterKind {
            Into::<T>::into(self.arguments[parameter as usize].clone())
        } else {
            panic!()
        }
    }
}

#[derive(Clone)]
pub struct TestParameters {
    parameters: Vec<&'static dyn TestParameter>,
}

static TTL_TEST_PARAMETER: TtlTestParameter = TtlTestParameter {};
static TOS_TEST_PARAMETER: TosTestParameter = TosTestParameter {};

impl TestParameters {
    pub fn new() -> Self {
        Self {
            parameters: vec![&TTL_TEST_PARAMETER, &TOS_TEST_PARAMETER],
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
        let mut arguments = Vec::<TestArgument>::new();
        for cmsg in cmsgs.iter() {
            if let Some(argument) = self
                .parameters
                .iter()
                .find_map(|param| param.argument_from(cmsg, logger.clone()))
            {
                arguments.push(argument);
            }
        }
        Ok(TestArguments { arguments })
    }
}

trait TestParameter {
    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError>;
    fn argument_from(&self, cmsg: &ControlMessageOwned, logger: Logger) -> Option<TestArgument>;
}

pub struct TtlTestParameter {}

impl TestParameter for TtlTestParameter {
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
        unsafe { Ok(libc::CMSG_SPACE(mem::size_of::<u32>() as libc::c_uint) as usize) }
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

pub struct TosTestParameter {}

impl TestParameter for TosTestParameter {
    fn configure_server(&self, socket: &UdpSocket, logger: Logger) -> Result<usize, StampError> {
        let recv_tos_value = true;
        IpRecvTos.set(&socket, &recv_tos_value).map_err(|e| {
            error!(
                logger,
                "There was an error configuring the server socket for the TOS test parameter: {}",
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
            ControlMessageOwned::Ipv4Tos(v) => Some(TestArgument::Ecn(v.into())),
            _ => {
                info!(
                    logger,
                    "{:?} does not appear to be an argument for the Tos test parameter.", cmsg
                );
                None
            }
        }
    }
}
