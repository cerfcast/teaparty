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
use clap::{arg, ArgMatches, Args, Command, FromArgMatches, Parser, Subcommand, ValueEnum};
use connection_generator::{ConnectionGenerator, ConnectionGeneratorError};
use core::fmt::Debug;
use custom_handlers::CustomHandlers;
use either::Either;
use etherparse::Ethernet2Header;
use ip::{DscpValue, EcnValue};
use monitor::Monitor;
use nix::sys::socket::Ipv6ExtHeader;
use ntp::NtpTime;
use parameters::{TestArgument, TestArguments, TestParameters};
use periodicity::Periodicity;
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use server::{ServerCancellation, ServerSocket, SessionData, Sessions};
use slog::{debug, error, info, trace, warn, Drain};
use stamp::{Ssid, StampError, StampMsg, StampMsgBody, StampResponseBodyType, MBZ_VALUE};
use std::io::ErrorKind::TimedOut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::netconf::NetConfiguration;
use crate::responder::Responder;

#[macro_use]
extern crate rocket;

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
mod periodicity;
mod responder;
mod server;
mod stamp;
mod test;
mod tlv;
mod util;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(default_value_t=IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    ip_addr: IpAddr,

    #[arg(default_value_t = 862)]
    port: u16,

    /// Specify the verbosity of output. Repeat to increase loquaciousness
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Specify the file to which log information should be written (defaults to terminal)
    #[arg(long, value_parser = clap::value_parser!(clio::ClioPath))]
    log_output: Option<clio::ClioPath>,
}

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

#[derive(Args, Debug)]
struct SenderArgs {
    #[arg(long)]
    ssid: Option<u16>,

    /// Include a malformed Tlv in the test packet
    #[arg(long)]
    malformed: Option<MalformedWhy>,

    /// Enable a non-default ECN for testing
    #[arg(long)]
    ecn: Option<EcnValue>,

    /// Enable a non-default DSCP for testing
    #[arg(long)]
    dscp: Option<DscpValue>,

    /// Enable a non-default TTL for testing
    #[arg(long)]
    ttl: Option<u8>,

    #[arg(long, default_value_t = 0)]
    src_port: u16,

    #[arg(long)]
    authenticated: Option<String>,

    #[arg(long)]
    destination_ext: Vec<Ipv6ExtensionHeaderArg>,

    #[arg(long)]
    hbh_ext: Vec<Ipv6ExtensionHeaderArg>,
}

#[derive(Args, Debug)]
struct ReflectorArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "Run teaparty in stateless mode."
    )]
    stateless: bool,

    #[arg(long, action = clap::ArgAction::Append, help = "Specify heartbeat message target and interval (in seconds) as [IP:PORT]@[Seconds]")]
    heartbeat: Vec<HeartbeatConfiguration>,

    #[arg(
        long,
        default_value_t = false,
        help = "Run teaparty in link-layer mode."
    )]
    link_layer: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Sender(SenderArgs),
    Reflector(ReflectorArgs),
}

#[derive(Debug, Clone)]
struct HeartbeatConfiguration {
    target: SocketAddr,
    interval: u64,
}

impl FromStr for HeartbeatConfiguration {
    type Err = clap::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
    args: Cli,
    command: Commands,
    mut extra_args: ArgMatches,
    logger: slog::Logger,
) -> Result<(), StampError> {
    let server_addr = SocketAddr::new(args.ip_addr, args.port);
    let (
        maybe_ssid,
        malformed,
        set_socket_ecn,
        set_socket_dscp,
        set_socket_ttl,
        src_port,
        authenticated,
        destination_exts,
        hbh_exts,
    ) = match command {
        Commands::Sender(SenderArgs {
            ssid,
            malformed,
            ecn,
            dscp,
            ttl,
            src_port,
            authenticated,
            destination_ext,
            hbh_ext,
        }) => (
            ssid.map(Ssid::Ssid),
            malformed,
            ecn,
            dscp,
            ttl,
            src_port,
            authenticated,
            destination_ext,
            hbh_ext,
        ),
        _ => panic!("The source port is somehow missing a value."),
    };

    info!(logger, "Connecting to the server at {}", server_addr);

    let server_socket = if server_addr.is_ipv4() {
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port))?
    } else {
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), src_port))?
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

    let destination_ext_body = destination_exts.iter().fold(vec![], |acc, new| {
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
            header_body: destination_ext_body,
        };
        let destination_ext_argument = TestArgument::HeaderOption(destination_ext_hdr.clone());
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

    let hbh_ext_body = hbh_exts.iter().fold(vec![], |acc, new| {
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
            header_body: hbh_ext_body,
        };
        let hbh_ext_argument = TestArgument::HeaderOption(hbh_ext_hdr.clone());
        configurator.add_configuration(
            netconf::NetConfigurationItemKind::ExtensionHeader,
            netconf::NetConfigurationArgument::ExtensionHeader(hbh_ext_hdr),
            NetConfiguration::CLIENT_SETTER,
        );
        test_arguments.add_argument(parameters::TestArgumentKind::HeaderOption, hbh_ext_argument);
    }

    let handlers = CustomHandlers::build();

    let mut tlvs = handlers
        .get_requests(Some(test_arguments), &mut extra_args)
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
        ssid: maybe_ssid.unwrap_or(stamp::Ssid::Ssid(0xeeff)),
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
    let mut fixup_session_data = SessionData::new(0);
    fixup_session_data.key = client_keymat.clone();
    let fixup_session_data = Some(fixup_session_data);

    for request_tlvs in client_msg.tlvs.tlvs.clone().iter() {
        if let Some(handler) = handlers.get_handler(request_tlvs.tpe) {
            let _ = handler.lock().unwrap().pre_send_fixup(
                &mut client_msg,
                &server_socket,
                &mut configurator,
                &fixup_session_data,
                logger.clone(),
            );
        }
    }

    configurator
        .configure(
            &mut client_msg,
            &server_socket,
            Some(handlers),
            logger.clone(),
        )
        .map_err(|v| StampError::Other(v.to_string()))?;

    let send_length = Responder::write(
        &Into::<Vec<u8>>::into(client_msg.clone()),
        &server_socket,
        &configurator,
        server_addr,
        logger.clone(),
    )?;

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
    let (server_response_len, _) = server_socket.recv_from(&mut server_response)?;

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
        return Err(e);
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
        return Err(e);
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
        return Err(StampError::Other(
            "Reflected contents are wrong.".to_string(),
        ));
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
        return Err(StampError::Other(
            "Reflected contents are wrong.".to_string(),
        ));
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
        return Err(StampError::Other(
            "Reflected contents are wrong.".to_string(),
        ));
    }

    Ok(())
}

fn server(args: Cli, command: Commands, logger: slog::Logger) -> Result<(), StampError> {
    // Make a runtime and then start it!
    let runtime = Arc::new(Asymmetry::new(Some(logger.clone())));
    {
        let runtime = runtime.clone();
        let _ = thread::spawn(move || {
            runtime.run();
        });
    }

    // The command is specific to the server. The match should *only* yield a
    // server command.
    let (stateless, heartbeats, link_layer) = match command {
        Commands::Reflector(ReflectorArgs {
            stateless,
            heartbeat,
            link_layer,
        }) => (stateless, heartbeat, link_layer),
        _ => {
            return Err(StampError::Other(
                "Somehow a non-server command was found during an invocation of the server.".into(),
            ))
        }
    };

    let server_socket_addr = SocketAddr::from((args.ip_addr, args.port));

    let udp_socket = UdpSocket::bind(server_socket_addr).map_err(|e| {
        error!(
            logger,
            "There was an error creating a server that listens on {}: {}", server_socket_addr, e
        );
        e
    })?;

    info!(logger, "Server listening on {}", server_socket_addr);

    let mut server_socket = ServerSocket::new(udp_socket, server_socket_addr);

    // Depending on whether the user wanted to look for sender packets at the
    // link layer or the network layer, configure a set of listeners (better known
    // as generators of packets).
    let listeners: Vec<Either<NetworkInterface, ServerSocket>> = if link_layer {
        // Find the interfaces that contain the IP address on which the user wants the
        // reflector to listen.
        let listening_interfaces = datalink::interfaces()
            .into_iter()
            .filter(|iface| {
                if args.ip_addr.is_unspecified() {
                    true
                } else {
                    iface.ips.iter().any(|ip| ip.contains(args.ip_addr))
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
        let configuration_warnings = server_socket.configure_cmsg().map_err(|e| {
            error!(
                logger,
                "There was an error configuring metadata parameters on the server socket: {}.", e
            );
            e
        })?;
        if !configuration_warnings.is_empty() {
            warn!(
                logger,
                "There were warnings generated when configuring the server socket: {}",
                configuration_warnings.join(";")
            );
        }
        server_socket.set_nonblocking(true).map_err(|e| {
            error!(
                logger,
                "Could not set the server socket as non blocking: {}", e
            );
            e
        })?;
        info!(logger, "Listening at the internet layer.");
        vec![either::Right(server_socket.clone())]
    };

    info!(logger, "listeners: {:?}", listeners);

    let sessions = if !stateless {
        Some(Sessions::new())
    } else {
        None
    };

    let periodical = Periodicity::new(
        server_socket.clone(),
        heartbeats.clone(),
        sessions.clone(),
        std::time::Duration::from_secs(10),
        runtime.clone(),
        logger.clone(),
    );

    let mut server_threads: Vec<JoinHandle<()>> = vec![];
    // Note: This signal handler is the first one that is registered. Rocket
    // will set another signal handler (for the meta thread), but it properly
    // dispatches to previously-registered signal handlers. Whew.
    let server_cancellation = ServerCancellation::new();
    {
        let mut periodical = periodical.clone();
        ctrlc::set_handler({
            let mut server_cancellation = server_cancellation.clone();
            let runtime = runtime.clone();
            move || {
                // It would be nice to log something here, but we have to be careful
                // about what can and cannot be done in a signal handler.
                server_cancellation.cancel();
                periodical
                    .stop()
                    .expect("Should have been able to stop the periodical.");
                runtime.cancel();
            }
        })
        .map_err(|e| StampError::SignalHandlerFailure(e.to_string()))?;
    }

    {
        let monitor = Monitor {
            sessions: sessions.clone(),
            periodic: periodical.clone(),
        };
        let logger = logger.clone();
        let _server_cancellation = server_cancellation.clone();
        thread::spawn(move || {
            meta::launch_meta(monitor, _server_cancellation, logger);
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
                connection_generator.configure_polling()?;
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
                        Ok((maybe_ethernet_hdr, ip_hdr, recv_data, client_address)) => {
                                    let parameters = TestParameters::new();

                                    // If the generator was not kind enough to supply an ethernet header, we will just use an empty
                                    // one to determine the arguments for the test.
                                    let ethernet_header = maybe_ethernet_hdr.unwrap_or(Ethernet2Header::from_bytes([0u8;14]));

                                    let arguments =
                                        parameters
                                        .get_arguments(&ethernet_header, &ip_hdr, logger.clone())
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
                            if ioe.kind() != TimedOut {
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

fn main() -> Result<(), StampError> {
    // These handlers are used only for generating command-line parameters.
    let tlv_handlers = CustomHandlers::build();
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
                "Could not open the given log file '{}': {:?}",
                output_path, log_output_file_open_error
            );
            println!("{}\n", error_description);
            println!("{}", basic_cli_parser.render_help().ansi());
            return Err(StampError::Other(error_description));
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

    let given_command = Commands::from_arg_matches(&matches);

    if given_command.is_err() {
        let parsing_error = given_command.unwrap_err();
        println!("{}\n", parsing_error);
        println!("{}", basic_cli_parser.render_help().ansi());
        return Err(StampError::Other(parsing_error.to_string()));
    }

    let given_command = given_command.unwrap();

    match &given_command {
        Commands::Reflector(ReflectorArgs {
            stateless: _,
            heartbeat: _,
            link_layer: _,
        }) => server(args, given_command, logger),
        Commands::Sender(SenderArgs {
            ssid: _,
            malformed: _,
            ecn: _,
            dscp: _,
            ttl: _,
            src_port: _,
            authenticated: _,
            destination_ext: _,
            hbh_ext: _,
        }) => client(args, given_command, matches, logger),
    }
}
