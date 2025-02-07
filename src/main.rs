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

use clap::{arg, ArgMatches, Args, Command, FromArgMatches, Parser, Subcommand, ValueEnum};
use connection_generator::{ConnectionGenerator, ConnectionGeneratorError};
use core::fmt::Debug;
use custom_handlers::CustomHandlers;
use handlers::Handlers;
use ip::{DscpValue, EcnValue};
use monitor::Monitor;
use nix::sys::socket::sockopt::Ipv4Tos;
use nix::sys::socket::SetSockOpt;
use ntp::NtpTime;
use parameters::{TestArgument, TestArguments, TestParameters};
use periodicity::Periodicity;
use pnet::datalink::{self, Channel, Config};
use server::{ServerCancellation, ServerSocket, Sessions};
use slog::{debug, error, info, trace, warn, Drain};
use stamp::{Ssid, StampError, StampMsg, StampMsgBody, StampResponseBodyType, MBZ_VALUE};
use std::io::ErrorKind::TimedOut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tlv::Tlvs;

#[macro_use]
extern crate rocket;

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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(default_value_t=IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    ip_addr: IpAddr,

    #[arg(default_value_t = 862)]
    port: u16,
}

#[derive(Clone, Debug, ValueEnum)]
enum MalformedWhy {
    BadFlags,
    BadLength,
}

#[derive(Args, Debug)]
struct SenderArgs {
    #[arg(long)]
    ssid: Option<u16>,

    /// Include a malformed Tlv in the test packet.
    #[arg(long)]
    malformed: Option<MalformedWhy>,

    /// Enable a non-default ECN for testing (ECT0)
    #[arg(long, default_value_t = false)]
    ecn: bool,

    /// Enable a non-default DSCP for testing (EF)
    #[arg(long, default_value_t = false)]
    dscp: bool,

    #[arg(long, default_value_t = 0)]
    src_port: u16,

    #[arg(long)]
    authenticated: Option<String>,
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
    handlers: Handlers,
    logger: slog::Logger,
) -> Result<(), StampError> {
    let server_addr = SocketAddr::new(args.ip_addr, args.port);
    let (maybe_ssid, malformed, use_ecn, use_dscp, src_port, authenticated) = match command {
        Commands::Sender(SenderArgs {
            ssid,
            malformed,
            ecn,
            dscp,
            src_port,
            authenticated,
        }) => (
            ssid.map(Ssid::Ssid),
            malformed,
            ecn,
            dscp,
            src_port,
            authenticated,
        ),
        _ => panic!("The source port is somehow missing a value."),
    };

    info!(logger, "Connecting to the server at {}", server_addr);

    let server_socket =
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port))?;

    let mut test_arguments = TestArguments::empty_arguments();

    let mut tos_byte: u8 = 0;

    if use_ecn {
        info!(
            logger,
            "About to configure the sending value of the IpV4 ECN on the server socket."
        );
        tos_byte |= Into::<u8>::into(EcnValue::Ect0);
        let set_tos_value = tos_byte as i32;
        if let Err(set_tos_value_err) = Ipv4Tos.set(&server_socket, &set_tos_value) {
            error!(
                logger,
                "There was an error configuring the client socket: {}", set_tos_value_err
            );
            return Err(Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            )));
        }

        let ecn_argment = TestArgument::Ecn(EcnValue::Ect0);
        test_arguments.add_argument(parameters::TestArgumentKind::Ecn, ecn_argment);

        info!(
            logger,
            "Done configuring the sending value of the IpV4 ECN on the server socket."
        );
    }

    if use_dscp {
        info!(
            logger,
            "About to configure the sending value of the IpV4 DSCP on the server socket."
        );
        tos_byte |= Into::<u8>::into(DscpValue::AF11);
        let set_tos_value = tos_byte as i32;
        if let Err(set_tos_value_err) = Ipv4Tos.set(&server_socket, &set_tos_value) {
            error!(
                logger,
                "There was an error configuring the client socket: {}", set_tos_value_err
            );
            return Err(Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            )));
        }

        let dscp_argment = TestArgument::Dscp(DscpValue::EF);
        test_arguments.add_argument(parameters::TestArgumentKind::Dscp, dscp_argment);

        info!(
            logger,
            "Done configuring the sending value of the IpV4 DSCP on the server socket."
        );
    }

    let mut tlvs = handlers.get_requests(Some(test_arguments), &mut extra_args);

    tlvs.extend(
        malformed
            .map(|o| match o {
                MalformedWhy::BadFlags => {
                    vec![tlv::Tlv::malformed_request(22)]
                }
                MalformedWhy::BadLength => {
                    vec![tlv::Tlv::malformed_tlv(22)]
                }
            })
            .unwrap_or_default(),
    );

    let tlvs = Tlvs {
        tlvs,
        malformed: None,
    };

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
    };

    let client_keymat = authenticated.map(|f| f.as_bytes().to_vec());

    client_msg.hmac = client_msg.authenticate(&client_keymat)?;

    let send_length =
        server_socket.send_to(&Into::<Vec<u8>>::into(client_msg.clone()), server_addr)?;
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

fn server(
    args: Cli,
    command: Commands,
    handlers: Handlers,
    logger: slog::Logger,
) -> Result<(), StampError> {
    // The command is specific to the server. The match should *only* yield a
    // server command.
    let (stateless, heartbeats) = match command {
        Commands::Reflector(ReflectorArgs {
            stateless,
            heartbeat,
        }) => (stateless, heartbeat),
        _ => {
            return Err(StampError::Other(
                "Somehow a non-server command was found during an invocation of the server.".into(),
            ))
        }
    };

    // Note: This signal handler is the first one that is registered. Rocket
    // will set another signal handler (for the meta thread), but it properly
    // dispatches to previously-registered signal handlers. Whew.
    let server_cancellation = ServerCancellation::new();
    ctrlc::set_handler({
        let mut server_cancellation = server_cancellation.clone();
        move || {
            // It would be nice to log something here, but we have to be careful
            // about what can and cannot be done in a signal handler.
            server_cancellation.cancel();
        }
    })
    .map_err(|e| StampError::SignalHandlerFailure(e.to_string()))?;

    // Find the interfaces that contain the IP address on which the user wants the
    // reflector to listen.
    let listening_interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            if args.ip_addr.is_unspecified() {
                true
            } else {
                iface.ips.iter().any(|ip| ip.contains(args.ip_addr))
            }
        })
        .collect();

    info!(
        logger,
        "Listening on {:?} interfaces.", listening_interfaces
    );

    if listening_interfaces.iter().any(|iface| iface.is_loopback()) {
        warn!(logger, "Reflector listening on loopback; duplicate response messages will be generated for connections on that interface.");
    }

    let bind_socket_addr = SocketAddr::from((args.ip_addr, args.port));
    info!(logger, "Bound to the server socket: {}", bind_socket_addr);

    let bind_result = UdpSocket::bind(bind_socket_addr).map_err(|e| {
        error!(
            logger,
            "There was an error creating the server socket: {}", e
        );
        Into::<StampError>::into(e)
    })?;

    // Make the socket non-blocking ...

    let socket = bind_result;
    socket.set_nonblocking(true).map_err(|e| {
        error!(
            logger,
            "There was an error setting the server server socket to non blocking: {}", e
        );
        Into::<StampError>::into(e)
    })?;

    let socket = ServerSocket::new(socket, bind_socket_addr);

    let responder = Arc::new(responder::Responder::new());

    let sessions = Sessions::new();

    let periodical = Periodicity::new(
        socket.clone(),
        heartbeats.clone(),
        sessions.clone(),
        std::time::Duration::from_secs(10),
        logger.clone(),
    );

    let mut server_threads: Vec<JoinHandle<()>> = vec![];

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

    for iface in listening_interfaces {
        let socket = socket.clone();
        server_threads.push({
            let logger = logger.clone();
            let responder = responder.clone();
            let sessions = sessions.clone();
            let handlers = handlers.clone();
            let server_cancellation = server_cancellation.clone();
            thread::spawn(move || {
                info!(
                    logger,
                    "Started thread {:?} to listen on interface {}.",
                    thread::current(),
                    iface.name
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

                let mut generator = ConnectionGenerator::from(pkt_receiver);

                loop {
                    if server_cancellation.is_cancelled() {
                        info!(
                            logger,
                            "Stopping thread {:?} that was listening on interface {}.",
                            thread::current(),
                            iface.name
                        );
                        break;
                    }
                    match generator.next(logger.clone(), bind_socket_addr) {
                        Ok((Some(ethernet_hdr), ip_hdr, recv_data, client_address)) => {
                                    let parameters = TestParameters::new();
                                    let arguments = parameters
                                        .get_arguments(&ethernet_hdr, &ip_hdr, logger.clone())
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
                                        let handlers = handlers.clone();
                                        let server = socket.clone();

                                        // If the server did not run forever, it may have been necessary
                                        // to `join` on this handle to make sure that the server did not
                                        // exit before the client was completely serviced.
                                        thread::spawn(move || {
                                            handlers::handler(
                                                received_time,
                                                &stamp_packets,
                                                arguments,
                                                sessions,
                                                !stateless,
                                                handlers,
                                                responder,
                                                server,
                                                client_address,
                                                logger,
                                            );
                                        });
                                    }

                                    info!( logger, "Passed off the connection from {:?} to the handler for handling.", client_address);
                                },
                        Ok(_) => {
                            todo!()
                        }
                        Err(ConnectionGeneratorError::Filtered) => {
                                trace!(logger, "Filtered. Skipping.");
                        }
                        Err(ConnectionGeneratorError::ExtractionError) => {
                                trace!(logger, "Failed to extract; assuming it was not for us.");
                        },
                        Err(ConnectionGeneratorError::IoError(ioe)) => {
                            if ioe.kind() != TimedOut {
                                error!(logger, "Error occurred while reading data frame from interface {}; processing of connections on this interface will terminate.", iface.name);
                                return;
                            }
                        },
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
    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(slog::Level::Debug)
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!("version" => "0.5"));

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
        }) => server(args, given_command, tlv_handlers, logger),
        Commands::Sender(SenderArgs {
            ssid: _,
            malformed: _,
            ecn: _,
            dscp: _,
            src_port: _,
            authenticated: _,
        }) => client(args, given_command, matches, tlv_handlers, logger),
    }
}
