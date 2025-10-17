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

use crate::{
    handlers::{
        TlvHandlerGenerator, TlvReflectorHandler, TlvReflectorHandlerConfigurator,
        TlvSenderHandlerConfigurator,
    },
    ip::ExtensionHeader,
};

use std::net::{SocketAddr, UdpSocket};

use clap::{ArgMatches, Command, FromArgMatches, Subcommand};
use slog::{info, Logger};

use crate::{
    handlers::{TlvRequestResult, TlvSenderHandler},
    netconf::NetConfigurator,
    netconf::{
        NetConfiguration, NetConfigurationArgument, NetConfigurationItem, NetConfigurationItemKind,
    },
    parameters::{TestArgumentKind, TestArguments},
    server::SessionData,
    stamp::{StampError, StampMsg},
    tlv::{self, Flags, Tlv},
};

#[derive(Default, Debug)]
pub struct ReflectedV6ExtensionHeaderDataTlv {
    headers: Vec<ExtensionHeader>,
}

#[derive(Subcommand, Clone, Debug)]
enum ReflectedV6ExtensionHeaderDataTlvCommand {
    ReflectedV6ExtensionHeaderData {
        #[arg(short, default_value_t = 8)]
        size: u16,

        #[arg(last = true)]
        next_tlv_command: Vec<String>,
    },
}

impl TlvReflectorHandler for ReflectedV6ExtensionHeaderDataTlv {
    fn tlv_name(&self) -> String {
        "Reflected IPv6 Extension Header Data".into()
    }

    fn tlv_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA].to_vec()
    }

    fn handle(
        &mut self,
        tlv: &tlv::Tlv,
        parameters: &TestArguments,
        _netconfig: &mut NetConfiguration,
        _client: SocketAddr,
        _session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        let mut response_tlv = tlv.clone();
        response_tlv.flags = Flags::new_response();

        // By default, assume that this TLV is unrecognized. When
        // data is actually put in it (pre_send_fixup), the value
        // will be changed!
        response_tlv.flags.set_unrecognized(true);

        self.headers = parameters.get_parameter_value(TestArgumentKind::HeaderOption)?;
        if !self.headers.is_empty() {
            info!(
                logger,
                "There are {} headers for this request: {:x?}",
                self.headers.len(),
                self.headers
            );
        }

        Ok(response_tlv)
    }

    fn pre_send_fixup(
        &mut self,
        response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "Reflected IPv6 Extension Header Data TLV is fixing up a response"
        );

        let header_options = response
            .tlvs
            .iter_mut()
            .filter(|tlv| tlv.tpe == Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA);

        for (extension_header, tlv) in self.headers.iter().as_slice().iter().zip(header_options) {
            match extension_header {
                ExtensionHeader::Six(ipv6_header) => {
                    // Punt if the IPv6 header is not at least 4 bytes!
                    if ipv6_header.header_body.len() < 4 {
                        info!(logger, "Skipping IPv6 Header that is shorter than 4 bytes.");
                        continue;
                    }
                    if ipv6_header.header_body.len() + 2 != (tlv.length as usize) {
                        info!(
                            logger,
                            "IPv6 extension header size does not match TLV length."
                        );
                        continue;
                    }
                    if !tlv.is_all_zeros() {
                        if tlv.length < 4 {
                            info!(
                        logger,
                        "Header Option TLV match contains a guard but is shorter than 4 bytes."
                    );
                            continue;
                        }
                        if ipv6_header.header_body[0..4] != tlv.value[0..4] {
                            info!(logger, "Header Option TLV match guard is false.");
                            continue;
                        }
                    }
                    // All good! Copy the data!
                    let mut header_raw = vec![
                        ipv6_header.header_next,
                        (((ipv6_header.header_body.len() + 2) / 8) - 1) as u8,
                    ];
                    ipv6_header
                        .header_body
                        .iter()
                        .for_each(|f| header_raw.push(*f));
                    tlv.value.copy_from_slice(&header_raw);
                    tlv.flags.set_unrecognized(false);

                    _config.add_configuration(
                        NetConfigurationItemKind::ExtensionHeader,
                        NetConfigurationArgument::ExtensionHeader(ipv6_header.clone()),
                        Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA,
                    );
                }
                ExtensionHeader::Four => {
                    // Nothing yet for extension headers for IPv4.
                }
            }
        }
        Ok(())
    }
}

impl NetConfigurator for ReflectedV6ExtensionHeaderDataTlv {
    fn handle_netconfig_error(
        &self,
        _response: &mut StampMsg,
        _socket: &UdpSocket,
        _item: NetConfigurationItem,
        _logger: Logger,
    ) {
        panic!("There was a net configuration error in a handler (Reflected IPv6 Extension Header Data) that does not set net configuration items.");
    }
}
impl TlvSenderHandler for ReflectedV6ExtensionHeaderDataTlv {
    fn tlv_name(&self) -> String {
        "Reflected IPv6 Extension Header Data".into()
    }

    fn tlv_sender_command(&self, existing: Command) -> Command {
        ReflectedV6ExtensionHeaderDataTlvCommand::augment_subcommands(existing)
    }

    fn tlv_sender_type(&self) -> Vec<u8> {
        [Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA].to_vec()
    }

    fn request(
        &mut self,
        _args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult {
        let maybe_our_command = ReflectedV6ExtensionHeaderDataTlvCommand::from_arg_matches(matches);
        if maybe_our_command.is_err() {
            return Ok(None);
        }
        let our_command = maybe_our_command.unwrap();
        let ReflectedV6ExtensionHeaderDataTlvCommand::ReflectedV6ExtensionHeaderData {
            size,
            next_tlv_command,
        } = our_command;

        let next_tlv_command = if !next_tlv_command.is_empty() {
            Some(next_tlv_command.join(" "))
        } else {
            None
        };

        Ok(Some((
            vec![Tlv {
                flags: Flags::new_request(),
                tpe: Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA,
                length: size,
                value: vec![0u8; size as usize],
            }],
            next_tlv_command,
        )))
    }

    fn pre_send_fixup(
        &mut self,
        response: &mut StampMsg,
        _socket: &UdpSocket,
        _config: &mut NetConfiguration,
        _session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "Reflected IPv6 Extension Header Data TLV is fixing up a response"
        );

        let header_options = response
            .tlvs
            .iter_mut()
            .filter(|tlv| tlv.tpe == Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA);

        for (extension_header, tlv) in self.headers.iter().as_slice().iter().zip(header_options) {
            match extension_header {
                ExtensionHeader::Six(ipv6_header) => {
                    // Punt if the IPv6 header is not at least 4 bytes!
                    if ipv6_header.header_body.len() < 4 {
                        info!(logger, "Skipping IPv6 Header that is shorter than 4 bytes.");
                        continue;
                    }
                    if ipv6_header.header_body.len() + 2 != (tlv.length as usize) {
                        info!(
                            logger,
                            "IPv6 extension header size does not match TLV length."
                        );
                        continue;
                    }
                    if !tlv.is_all_zeros() {
                        if tlv.length < 4 {
                            info!(
                        logger,
                        "Header Option TLV match contains a guard but is shorter than 4 bytes."
                    );
                            continue;
                        }
                        if ipv6_header.header_body[0..4] != tlv.value[0..4] {
                            info!(logger, "Header Option TLV match guard is false.");
                            continue;
                        }
                    }
                    // TODO: Determine how match configuration is positioned (i.e., does it include the next header type and the extension header length?)
                    let mut header_raw =
                        vec![0, (((ipv6_header.header_body.len() + 2) / 8) - 1) as u8];
                    ipv6_header
                        .header_body
                        .iter()
                        .for_each(|f| header_raw.push(*f));
                    tlv.value.copy_from_slice(&header_raw);
                    tlv.flags.set_unrecognized(false);

                    _config.add_configuration(
                        NetConfigurationItemKind::ExtensionHeader,
                        NetConfigurationArgument::ExtensionHeader(ipv6_header.clone()),
                        Tlv::REFLECTED_IPV6_EXTENSION_HEADER_DATA,
                    );
                }
                ExtensionHeader::Four => {
                    // Nothing yet for v4.
                }
            }
        }
        Ok(())
    }
}

impl TlvSenderHandlerConfigurator for ReflectedV6ExtensionHeaderDataTlv {}
impl TlvReflectorHandlerConfigurator for ReflectedV6ExtensionHeaderDataTlv {}

pub struct V6ExtensionHeadersReflectionTlvReflectorConfig {}

impl TlvHandlerGenerator for V6ExtensionHeadersReflectionTlvReflectorConfig {
    fn tlv_reflector_name(&self) -> String {
        "extension-headers".into()
    }

    fn generate(&self) -> Box<dyn TlvReflectorHandlerConfigurator + Send> {
        Box::new(ReflectedV6ExtensionHeaderDataTlv::default())
    }
}
