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

use asymmetry::Asymmetry;
use clap::{ArgMatches, Args, Command, FromArgMatches, ValueEnum};
use clio::ClioPath;
use connection_generator::{ConnectionGenerator, ConnectionGeneratorError};
use core::fmt::Debug;
use custom_handlers::CustomSenderHandlers;
use either::Either;
use etherparse::Ethernet2Header;
use monitor::Monitor;
use nix::sys::socket::Ipv6ExtHeader;
use ntp::NtpTime;
use parameters::{TestArgument, TestArguments, TestParameters};
use periodicity::Periodicity;
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use server::{ServerCancellation, ServerSocket, SessionData, Sessions};
use slog::{debug, error, info, o, trace, warn, Drain, Logger};
use stamp::{StampError, StampMsg, StampMsgBody, StampResponseBodyType, MBZ_VALUE};
use std::io::ErrorKind::{TimedOut, WriteZero};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::app::{
    extract_configuration, Cli, ClientError, ReflectorArgs, ReflectorGeneralConfiguration,
    SenderArgs, ServerError, TeapartyError, TeapartyModes,
};
use crate::connection_generator::{Connection, ConnectionInformation};
use crate::custom_handlers::CustomReflectorHandlersGenerators;
use crate::ip::ExtensionHeader;
use crate::netconf::NetConfiguration;
use crate::responder::Responder;

extern crate rocket;

mod app;
mod asymmetry;
mod connection_generator;
mod custom_handlers;
mod handlers;
mod ip;
mod meta;
mod monitor;
mod netconf;
mod ntp;
mod os;
mod parameters;
mod parsers;
mod periodicity;
mod responder;
mod server;
mod stamp;
mod test;
mod tlv;
mod util;

mod tlvs;

#[derive(Clone, Debug, ValueEnum)]
enum MalformedWhy {
    BadFlags,
    BadLength,
}

#[derive(Clone, Debug)]
struct Ipv6ExtensionHeaderArg {
    tipe: u8,
    body: Vec<u8>,
}

impl FromStr for Ipv6ExtensionHeaderArg {
    type Err = clap::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let components = s.split(",").collect::<Vec<&str>>();

        if components.len() < 2 || components.len() > 3 {
            return Err(clap::error::Error::new(
                clap::error::ErrorKind::InvalidValue,
            ));
        }

        let maybe_tipe = components[0];
        let maybe_len = components[1];

        let tipe = maybe_tipe
            .parse::<u8>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
        let len = maybe_len
            .parse::<u16>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
        let body = if components.len() > 2 {
            let maybe_body = components[2];
            let body_format = maybe_body
                .parse::<u8>()
                .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
            vec![body_format; len as usize]
        } else {
            vec![0u8; len as usize]
        };

        Ok(Self { tipe, body })
    }
}

#[derive(Debug, Clone)]
struct HeartbeatConfiguration {
    target: SocketAddr,
    interval: u64,
}

impl FromStr for HeartbeatConfiguration {
    type Err = clap::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        println!("s: {s}");
        let components = s.split("@").collect::<Vec<&str>>();

        if components.len() != 2 {
            return Err(clap::error::Error::new(
                clap::error::ErrorKind::InvalidValue,
            ));
        }

        let maybe_target = components[0];
        let maybe_interval = components[1];

        let target = maybe_target
            .parse::<SocketAddr>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;
        let interval = maybe_interval
            .parse::<u64>()
            .map_err(|_| clap::error::Error::new(clap::error::ErrorKind::InvalidValue))?;

        Ok(Self { target, interval })
    }
}

fn client(
    args: SenderArgs,
    tlv_args: Option<ArgMatches>,
    logger: slog::Logger,
) -> Result<(), TeapartyError> {
    let SenderArgs {
        ip_addr,
        port,
        ssid: maybe_ssid,
        malformed,
        ecn: set_socket_ecn,
        dscp: set_socket_dscp,
        ttl: set_socket_ttl,
        src_port,
        authenticated,
        destination_ext,
        hbh_ext,
    } = args;

    let server_addr = SocketAddr::new(ip_addr, port);
    info!(logger, "Connecting to the server at {}", server_addr);

    let server_socket = if server_addr.is_ipv4() {
        UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port.unwrap_or_default(),
        ))
        .map_err(StampError::Io)?
    } else {
        UdpSocket::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            src_port.unwrap_or_default(),
        ))
        .map_err(StampError::Io)?
    };

    let mut test_arguments: TestArguments = Default::default();

    let mut configurator = NetConfiguration::new();
    if let Some(socket_ecn) = set_socket_ecn {
        let ecn_argment = TestArgument::Ecn(socket_ecn);
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::Ecn,
            netconf::NetConfigurationArgument::Ecn(socket_ecn),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(parameters::TestArgumentKind::Ecn, ecn_argment);
    }
    if let Some(socket_dscp) = set_socket_dscp {
        let dscp_argment = TestArgument::Dscp(socket_dscp);
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::Dscp,
            netconf::NetConfigurationArgument::Dscp(socket_dscp),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(parameters::TestArgumentKind::Dscp, dscp_argment);
    }
    if let Some(socket_ttl) = set_socket_ttl {
        let ttl_argument = TestArgument::Ttl(socket_ttl);
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::Ttl,
            netconf::NetConfigurationArgument::Ttl(socket_ttl),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(parameters::TestArgumentKind::Ttl, ttl_argument);
    }

    let destination_ext_body = destination_ext.iter().fold(vec![], |acc, new| {
        [
            acc.as_slice(),
            &[new.tipe, new.body.len() as u8],
            new.body.as_slice(),
        ]
        .concat()
    });

    if !destination_ext_body.is_empty() {
        let destination_ext_hdr = Ipv6ExtHeader {
            header_type: nix::sys::socket::Ipv6ExtHeaderType::Dst,
            header_next: 0x0,
            header_body: destination_ext_body,
        };
        let destination_ext_argument =
            TestArgument::HeaderOption(ExtensionHeader::Six(destination_ext_hdr.clone()));
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::ExtensionHeader,
            netconf::NetConfigurationArgument::ExtensionHeader(destination_ext_hdr),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(
            parameters::TestArgumentKind::HeaderOption,
            destination_ext_argument,
        );
    }

    let hbh_ext_body = hbh_ext.iter().fold(vec![], |acc, new| {
        [
            acc.as_slice(),
            &[new.tipe, new.body.len() as u8],
            new.body.as_slice(),
        ]
        .concat()
    });

    if !hbh_ext_body.is_empty() {
        let hbh_ext_hdr = Ipv6ExtHeader {
            header_type: nix::sys::socket::Ipv6ExtHeaderType::HopByHop,
            header_next: 0x0,
            header_body: hbh_ext_body,
        };
        let hbh_ext_argument =
            TestArgument::HeaderOption(ExtensionHeader::Six(hbh_ext_hdr.clone()));
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::ExtensionHeader,
            netconf::NetConfigurationArgument::ExtensionHeader(hbh_ext_hdr),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(parameters::TestArgumentKind::HeaderOption, hbh_ext_argument);
    }

    let mut handlers = CustomSenderHandlers::build();

    let mut tlvs = handlers
        .get_requests(Some(test_arguments), tlv_args)
        .map_err(|e| TeapartyError::Client(ClientError::Cli(e)))?
        .unwrap_or_default();

    malformed.iter().for_each(|o| match o {
        MalformedWhy::BadFlags => {
            tlvs.add_tlv(tlv::Tlv::malformed_request(22))
                .expect("Should be able to add a malformed TLV to the test packet.");
        }
        MalformedWhy::BadLength => {
            tlvs.add_tlv(tlv::Tlv::malformed_request(22))
                .expect("Should be able to add a malformed TLV to the test packet.");
        }
    });

    let body = if authenticated.is_some() {
        TryInto::<StampMsgBody>::try_into([MBZ_VALUE; 68].as_slice())?
    } else {
        TryInto::<StampMsgBody>::try_into([MBZ_VALUE; 28].as_slice())?
    };

    let mut client_msg = StampMsg {
        sequence: 0x22,
        time: NtpTime::now(),
        error: Default::default(),
        ssid: maybe_ssid.unwrap_or(stamp::Ssid::Mbz(Default::default())),
        body,
        hmac: None,
        tlvs,
        raw_length: None,
    };

    let client_keymat = authenticated.map(|f| f.as_bytes().to_vec());

    client_msg.hmac = client_msg.authenticate(&client_keymat)?;

    // Let the handlers fixup according to this session data.
    // Note: The session data here is only populated with the key -- future features
    // may need other parts of the session data.
    let mut fixup_session_data = SessionData::new(None);
    fixup_session_data.key = client_keymat.clone();
    let fixup_session_data = Some(fixup_session_data);

    for request_tlvs in client_msg.tlvs.tlvs.clone().iter() {
        if let Some(handler) = handlers.get_handler(request_tlvs.tpe) {
            let _ = handler.pre_send_fixup(
                &mut client_msg,
                &server_socket,
                &mut configurator,
                &fixup_session_data,
                logger.clone(),
            );
        }
    }

    configurator
        .configure(&mut client_msg, &server_socket, &handlers, logger.clone())
        .map_err(|v| StampError::Other(v.to_string()))?;

    let send_length = Responder::write(
        &Into::<Vec<u8>>::into(client_msg.clone()),
        &server_socket,
        &configurator,
        server_addr,
        logger.clone(),
    )
    .map_err(StampError::Io)?;

    info!(
        logger,
        "Sent a stamp message that is {} bytes long.", send_length
    );

    info!(logger, "Stamp message sent: {:?}", client_msg);
    info!(
        logger,
        "Stamp message sent (bytes): {:x?}",
        Into::<Vec<u8>>::into(client_msg.clone())
    );

    let mut server_response = vec![0u8; 1500];
    let (server_response_len, _) = server_socket
        .recv_from(&mut server_response)
        .map_err(StampError::Io)?;

    info!(
        logger,
        "Got a response back from the server that is {} bytes long.", server_response_len
    );
    debug!(
        logger,
        "Response: {:x?}",
        &server_response[0..server_response_len]
    );

    let deserialized_response =
        TryInto::<StampMsg>::try_into(&server_response[0..server_response_len]);

    if let Err(e) = deserialized_response {
        error!(logger, "Could not deserialize the server's response: {}", e);
        return Err(e.into());
    }

    let deserialized_response = deserialized_response.unwrap();
    info!(logger, "Deserialized response: {:?}", deserialized_response);

    let authentication_result = match deserialized_response.authenticate(&client_keymat) {
        Ok(checked_hash) => {
            if checked_hash == deserialized_response.hmac {
                Ok(())
            } else {
                info!(
                    logger,
                    "Wanted HMAC {:x?} and got HMAC {:x?} (used {:x?} for keymat)",
                    checked_hash,
                    client_msg.hmac,
                    client_keymat
                );
                Err(StampError::InvalidSignature)
            }
        }
        Err(e) => Err(e),
    };

    if let Err(e) = authentication_result {
        warn!(
            logger,
            "An authenticated packet arrived which could not be validated: {}", e
        );
        return Err(e.into());
    }

    // Let's compare what we got back to what we sent!

    let reflected_time = match &deserialized_response.body {
        StampMsgBody::Response(StampResponseBodyType::Authenticated(body)) => &body.sent_time,
        StampMsgBody::Response(StampResponseBodyType::UnAuthenticated(body)) => &body.sent_time,
        _ => unreachable!(),
    };
    if reflected_time != &client_msg.time {
        warn!(
            logger,
            "The reflected packet did not contain the time that was sent (expected {:?} but got {:?})",client_msg.time, reflected_time
        );
        return Err(TeapartyError::Stamp(StampError::Other(
            "Reflected contents are wrong.".to_string(),
        )));
    }

    let reflected_error = match &deserialized_response.body {
        StampMsgBody::Response(StampResponseBodyType::Authenticated(body)) => &body.sent_error,
        StampMsgBody::Response(StampResponseBodyType::UnAuthenticated(body)) => &body.sent_error,
        _ => unreachable!(),
    };
    if reflected_error != &client_msg.error {
        warn!(
            logger,
            "The reflected packet did not contain the error estimate that was sent (expected {:?} but got {:?})",client_msg.error, reflected_error
        );
        return Err(StampError::Other("Reflected contents are wrong.".to_string()).into());
    }

    let reflected_sequenceno = match &deserialized_response.body {
        StampMsgBody::Response(StampResponseBodyType::Authenticated(body)) => &body.sent_sequence,
        StampMsgBody::Response(StampResponseBodyType::UnAuthenticated(body)) => &body.sent_sequence,
        _ => unreachable!(),
    };
    if reflected_sequenceno != &client_msg.sequence {
        warn!(
            logger,
            "The reflected packet did not contain the sequence number that was sent (expected {:?} but got {:?})",client_msg.sequence, reflected_sequenceno
        );
        return Err(StampError::Other("Reflected contents are wrong.".to_string()).into());
    }

    Ok(())
}

fn servers(config: &Option<ClioPath>, logger: Logger) -> Result<(), TeapartyError> {
    if let Some(config_path) = config {
        let valid_yaml = extract_configuration(config_path.clone())?;
        let reflector_configurations: Vec<_> = if let Some(config_yaml) = valid_yaml.as_vec() {
            config_yaml
                .iter()
                .map(
                    |config_sequence_node| match TryInto::<ReflectorGeneralConfiguration>::try_into(
                        config_sequence_node,
                    ) {
                        Ok(reflector_configuration) => Ok(reflector_configuration),
                        Err(e) => Err(TeapartyError::Server(app::ServerError::Config(format!(
                            "Could not parse reflector configuration: {e:?}"
                        )))),
                    },
                )
                .collect()
        } else {
            return Err(TeapartyError::Server(app::ServerError::Config("Every element in the top-level sequence of configuration items must be a YAML mapping".to_string())));
        };

        let valid_reflector_configurations: Vec<_> = reflector_configurations
            .iter()
            .filter_map(|f| match f {
                Err(e) => {
                    error!(logger, "Could not parse configuration section: {e:?}");
                    None
                }
                Ok(c) => Some(c),
            })
            .cloned()
            .collect();
        let server_cancellation = ServerCancellation::new();

        let mut ctrlc_server_cancellation = server_cancellation.clone();

        ctrlc::set_handler(move || ctrlc_server_cancellation.cancel())
            .map_err(|e| StampError::SignalHandlerFailure(e.to_string()))?;

        let mut running_servers: Vec<JoinHandle<_>> = vec![];

        let mut nameless_server_count = 0;

        for configuration in valid_reflector_configurations {
            let server_name = if let Some(configured_name) = &configuration.name {
                configured_name.clone()
            } else {
                nameless_server_count += 1;
                format!("reflector_instance_{nameless_server_count}")
            };

            let server_cancellation = server_cancellation.clone();
            let logger = logger.new(o!("instance" => server_name));
            running_servers.push(thread::spawn(move || {
                server(
                    configuration.clone(),
                    server_cancellation.clone(),
                    logger.clone(),
                )
            }));
        }

        for running_server in running_servers {
            running_server
                .join()
                .map_err(|e| TeapartyError::Server(ServerError::Runtime(format!("{e:?}"))))??;
        }

        Ok(())
    } else {
        Err(TeapartyError::Server(app::ServerError::Config(
            "Every element in the top-level sequence of configuration items must be a YAML mapping"
                .to_string(),
        )))
    }
}

fn server(
    reflector_config: ReflectorGeneralConfiguration,
    server_cancellation: ServerCancellation,
    logger: slog::Logger,
) -> Result<(), TeapartyError> {
    // Make a runtime and then start it!
    let runtime = Arc::new(Asymmetry::new(Some(logger.clone())));
    {
        let runtime = runtime.clone();
        let _ = thread::spawn(move || {
            runtime.run();
        });
    }

    // TODO: Handle configurations for Tlv Handlers.
    let reflector_handler_generator = CustomReflectorHandlersGenerators::new();

    let server_socket_addr = reflector_config.listen_addr.addr;

    let udp_socket = UdpSocket::bind(server_socket_addr)
        .map_err(|e| {
            error!(
                logger,
                "There was an error creating a server that listens on {}: {}",
                server_socket_addr,
                e
            );
            e
        })
        .map_err(StampError::Io)?;

    info!(logger, "Server listening on {}", server_socket_addr);

    let mut server_socket = ServerSocket::new(udp_socket, server_socket_addr);

    // Depending on whether the user wanted to look for sender packets at the
    // link layer or the network layer, configure a set of listeners (better known
    // as generators of packets).
    let listeners: Vec<Either<NetworkInterface, ServerSocket>> = if reflector_config.link_layer {
        // Find the interfaces that contain the IP address on which the user wants the
        // reflector to listen.
        let listening_interfaces = datalink::interfaces()
            .into_iter()
            .filter(|iface| {
                if reflector_config.listen_addr.addr.ip().is_unspecified() {
                    true
                } else {
                    iface
                        .ips
                        .iter()
                        .any(|ip| ip.contains(reflector_config.listen_addr.addr.ip()))
                }
            })
            .collect::<Vec<_>>();

        info!(
            logger,
            "Listening at the link layer on {:?} interfaces.", listening_interfaces
        );

        if listening_interfaces.iter().any(|iface| iface.is_loopback()) {
            warn!(logger, "Reflector listening on loopback; duplicate response messages will be generated for connections on that interface.");
        }
        listening_interfaces
            .into_iter()
            .map(either::Left)
            .collect::<Vec<_>>()
    } else {
        // Configure the required parameters for the server socket so that we are able to read
        // information from the IP header about a received packet.
        let configuration_warnings = server_socket
            .configure_cmsg()
            .map_err(|e| {
                error!(
                    logger,
                    "There was an error configuring metadata parameters on the server socket: {}.",
                    e
                );
                e
            })
            .map_err(StampError::Io)?;
        if !configuration_warnings.is_empty() {
            warn!(
                logger,
                "There were warnings generated when configuring the server socket: {}",
                configuration_warnings.join(";")
            );
        }
        server_socket
            .set_nonblocking(true)
            .map_err(|e| {
                error!(
                    logger,
                    "Could not set the server socket as non blocking: {}", e
                );
                e
            })
            .map_err(StampError::Io)?;
        info!(logger, "Listening at the internet layer.");
        vec![either::Right(server_socket.clone())]
    };

    info!(logger, "listeners: {:?}", listeners);

    let sessions = if !reflector_config.stateless {
        Some(Sessions::new())
    } else {
        None
    };

    let periodical = Periodicity::new(
        server_socket.clone(),
        reflector_config.heartbeat.clone(),
        sessions.clone(),
        std::time::Duration::from_secs(10),
        runtime.clone(),
        logger.clone(),
    );

    let mut server_threads: Vec<JoinHandle<()>> = vec![];
    // Note: This signal handler is the first one that is registered. Rocket
    // will set another signal handler (for the meta thread), but it properly
    // dispatches to previously-registered signal handlers. Whew.

    {
        let monitor = Monitor {
            sessions: sessions.clone(),
            periodic: periodical.clone(),
        };
        let logger = logger.clone();
        let _server_cancellation = server_cancellation.clone();

        let meta_listen_addr = match reflector_config.meta_addr {
            Some(addr) => addr.addr,
            None => Into::<SocketAddr>::into((server_socket_addr.ip(), 8000)),
        };

        thread::spawn(move || {
            meta::launch_meta(monitor, meta_listen_addr, _server_cancellation, logger);
        })
    };

    for listener in listeners {
        // Depending on the listener, the generator will need to get constructed differently.
        let mut generator = match listener {
            either::Left(iface) => {
                info!(
                    logger,
                    "Started server to listen on interface {}.", iface.name
                );

                let (_, pkt_receiver) = match datalink::channel(
                    &iface,
                    Config {
                        read_timeout: Some(Duration::from_micros(3)),
                        ..Default::default()
                    },
                )
                .unwrap()
                {
                    Channel::Ethernet(sender, receiver) => (sender, receiver),
                    _ => panic!("Bad channel received!"),
                };

                ConnectionGenerator::from(pkt_receiver)
            }
            either::Right(sock) => {
                let mut connection_generator = ConnectionGenerator::from(sock);
                connection_generator
                    .configure_polling()
                    .map_err(StampError::Io)?;
                connection_generator
            }
        };

        // No matter what is the type of the listener, now that there is a generator it can be
        // used to get packets sent by clients. We create a new thread to service each generator.

        let responder = Arc::new(responder::Responder::new());
        let responder_canceller = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // TODO
        #[allow(unused)]
        let responder_thread = {
            let responder = responder.clone();
            let server = server_socket.clone();
            let logger = logger.clone();
            let responder_canceller = responder_canceller.clone();
            thread::spawn(move || {
                responder.run(server, responder_canceller, logger);
            })
        };

        server_threads.push({
            let logger = logger.clone();
            let responder = responder.clone();
            let sessions = sessions.clone();
            let server_cancellation = server_cancellation.clone();
            let server_socket = server_socket.clone();
            let reflector_handler_generator = reflector_handler_generator.clone();
            let runtime = runtime.clone();
            thread::spawn(move || {
                loop {
                    if server_cancellation.is_cancelled() {
                        info!(
                            logger,
                            "Stopping thread {:?}",
                            thread::current(),
                        );
                        break;
                    }
                    match generator.next(logger.clone(), server_socket_addr) {
                        Ok(Connection{information: ConnectionInformation{ethernet: maybe_ethernet_hdr, raw_network: maybe_raw_ip_hdr, network: ip_hdr}, body: recv_data, addr: client_address}) => {


                                    let parameters = TestParameters::new();

                                    // If the generator was not kind enough to supply an ethernet header, we will just use an empty
                                    // one to determine the arguments for the test.
                                    let ethernet_header = maybe_ethernet_hdr.unwrap_or(Ethernet2Header::from_bytes([0u8;14]));

                                    let raw_ip_hdr = maybe_raw_ip_hdr.unwrap_or_default();

                                    let arguments =
                                        parameters
                                        .get_arguments(raw_ip_hdr, &ethernet_header, &ip_hdr, logger.clone())
                                        .expect("Could not get the arguments from the ip header");

                                    let received_time = chrono::Utc::now();

                                    info!(
                                        logger,
                                        "Got a connection from {:?} at {}",
                                        client_address,
                                        received_time
                                    );

                                    {
                                        let logger = logger.clone();
                                        let recv_msg_size = recv_data.len();
                                        let arguments = arguments.clone();
                                        let stamp_packets = recv_data[0..recv_msg_size].to_vec();
                                        let responder = responder.clone();
                                        let sessions = sessions.clone();
                                        let server_socket = server_socket.clone();
                                        let handlers = reflector_handler_generator.generate();
                                        let runtime = runtime.clone();
                                        // If the server did not run forever, it may have been necessary
                                        // to `join` on this handle to make sure that the server did not
                                        // exit before the client was completely serviced.
                                        thread::spawn(move || {
                                            handlers::handler(
                                                received_time,
                                                &stamp_packets,
                                                arguments,
                                                sessions,
                                                responder,
                                                server_socket,
                                                client_address,
                                                handlers,
                                                runtime,
                                                logger,
                                            );
                                        });
                                    }

                                    info!( logger, "Passed off the connection from {:?} to the handler for handling.", client_address);
                                },
                        Err(ConnectionGeneratorError::Filtered) => {
                                trace!(logger, "Filtered. Skipping.");
                        }
                        Err(ConnectionGeneratorError::ExtractionError) => {
                                trace!(logger, "Failed to extract; assuming it was not for us.");
                        },
                        Err(ConnectionGeneratorError::IoError(ioe)) => {
                            if ioe.kind() != TimedOut && ioe.kind() != WriteZero {
                                error!(logger, "Error occurred while reading data frame: {:?}; processing of connections on this interface will terminate.", ioe.kind());
                                return;
                            }
                        },
                        Err(ConnectionGeneratorError::WouldBlock) => {
                            trace!(logger, "There was no data available to be read from the network (... would block).")
                        }
                    }
                }
            })
        })
    }
    server_threads.into_iter().for_each(|f| {
        info!(logger, "Waiting for thread {:?} to stop", f.thread());
        if let Err(e) = f.join() {
            error!(logger, "An error occurred while joining thread: {:?}", e);
        }
    });
    Ok(())
}

fn main() -> Result<(), TeapartyError> {
    // These handlers are used only for generating command-line parameters.
    let tlv_handlers = CustomSenderHandlers::build();
    let tlvs_command = tlv_handlers.get_cli_commands();

    let sender_command = Command::new("sender");
    let sender_command = SenderArgs::augment_args(sender_command);
    let sender_command = sender_command.subcommand(tlvs_command);

    let reflector_command = Command::new("reflector");
    let reflector_command = ReflectorArgs::augment_args(reflector_command);

    let command = Command::new("Commands")
        .subcommand(sender_command)
        .subcommand(reflector_command);

    let mut basic_cli_parser = Cli::augment_args(command);

    let matches = basic_cli_parser.clone().get_matches();
    let args = Cli::from_arg_matches(&matches).unwrap();

    let log_level = if args.debug > 2 {
        slog::Level::Trace
    } else if args.debug > 1 {
        slog::Level::Debug
    } else if args.debug > 0 {
        slog::Level::Info
    } else {
        slog::Level::Error
    };

    let logger = if let Some(output_path) = &args.log_output {
        let log_output_open_result = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(output_path.path());

        if let Err(log_output_file_open_error) = log_output_open_result {
            let error_description = format!(
                "Could not open the given log file '{output_path}': {log_output_file_open_error:?}"
            );
            println!("{error_description}\n");
            println!("{}", basic_cli_parser.render_help().ansi());
            return Err(StampError::Other(error_description).into());
        }
        let decorator = slog_term::PlainSyncDecorator::new(log_output_open_result.unwrap());

        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(log_level)
            .fuse();
        slog::Logger::root(drain, slog::o!("version" => "0.5"))
    } else {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());

        let drain = slog_term::FullFormat::new(decorator)
            .build()
            .filter_level(log_level)
            .fuse();
        slog::Logger::root(drain, slog::o!("version" => "0.5"))
    };

    let teaparty_mode = TeapartyModes::from_arg_matches(&matches);

    match teaparty_mode {
        Err(e) => {
            println!("{e}\n");
            println!("{}", basic_cli_parser.render_help().ansi());
            Err(StampError::Other(e.to_string()).into())
        }
        Ok(teaparty_mode) => match &teaparty_mode {
            TeapartyModes::Reflector(ReflectorArgs { config }) => servers(config, logger),
            TeapartyModes::Sender(e) => {
                // Dig down and get the (potentially present "tlvs").
                let tlv_args = matches
                    .subcommand_matches("sender")
                    .and_then(|sender_matches| sender_matches.subcommand_matches("tlvs").cloned());
                client(e.clone(), tlv_args, logger)
            }
        },
    }
}
