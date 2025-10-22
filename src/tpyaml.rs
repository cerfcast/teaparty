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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::app::{ServerError, TeapartyError};
use yaml_rust2::Yaml;

#[derive(Clone, Debug)]
pub struct YamlSocketAddr<const T: u16> {
    pub addr: SocketAddr,
}

impl<const T: u16> Default for YamlSocketAddr<T> {
    fn default() -> Self {
        Self {
            addr: (Ipv6Addr::UNSPECIFIED, T).into(),
        }
    }
}
impl<const T: u16> YamlSocketAddr<T> {
    pub const DEFAULT_PORT: u16 = T;
}

impl<const T: u16> From<SocketAddr> for YamlSocketAddr<T> {
    fn from(value: SocketAddr) -> Self {
        YamlSocketAddr {
            addr: (
                value.ip(),
                if value.port() != 0 {
                    value.port()
                } else {
                    YamlSocketAddr::<T>::DEFAULT_PORT
                },
            )
                .into(),
        }
    }
}
impl<const T: u16> FromStr for YamlSocketAddr<T> {
    type Err = clap::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First, split at last :
        let splits: Vec<_> = s.split(':').collect();

        // We'll try to consider that a port.
        if let Some(maybe_port) = splits.last() {
            // That means that all the values before it are part of an IP address.
            let ip = splits[0..splits.len() - 1].join(":");

            // If that worked, then we're in business.
            if let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), maybe_port.parse::<u16>()) {
                return Ok(YamlSocketAddr {
                    addr: (ip, port).into(),
                });
            }
        }

        // Otherwise, it _seems_ like everything that was given by the user is an IP!
        let ip = s
            .parse::<IpAddr>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
        Ok(YamlSocketAddr {
            addr: (ip, Self::DEFAULT_PORT).into(),
        })
    }
}

impl<const T: u16> TryInto<YamlSocketAddr<T>> for &Yaml {
    type Error = TeapartyError;

    fn try_into(self) -> Result<YamlSocketAddr<T>, Self::Error> {
        if let Some(yaml) = self.as_hash() {
            let mut addr = Into::<SocketAddr>::into((Ipv4Addr::UNSPECIFIED, 0));

            if let Some(value) = yaml
                .get(&Yaml::String("ip".to_string()))
                .and_then(|f| f.as_str())
            {
                addr.set_ip(value.parse::<IpAddr>().map_err(|e| {
                    TeapartyError::Server(ServerError::Config(format!(
                        "Could not parse IP address: {e}"
                    )))
                })?)
            }
            if let Some(value) = yaml
                .get(&Yaml::String("port".to_string()))
                .and_then(|f| f.as_i64())
            {
                addr.set_port(u16::try_from(value).map_err(|e| {
                    TeapartyError::Server(ServerError::Config(format!(
                        "Could not parse port number: {e}"
                    )))
                })?)
            }
            Ok(YamlSocketAddr { addr })
        } else {
            Err(TeapartyError::Server(ServerError::Config(
                "Invalid configuration for socket address".to_string(),
            )))
        }
    }
}
