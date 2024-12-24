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
use clap::{Parser, Subcommand, ValueEnum};
use core::fmt::Debug;
use custom_handlers::CustomHandlers;
use handlers::Handlers;
use mio::{Interest, Token};
use monitor::Monitor;
use nix::errno::Errno;
use nix::sys::socket::sockopt::Ipv4Tos;
use nix::sys::socket::{recvmsg, MsgFlags, SetSockOpt, SockaddrIn};
use ntp::NtpTime;
use parameters::{DscpValue, EcnValue, TestArgument, TestArguments, TestParameters};
use periodicity::Periodicity;
use server::{ServerSocket, Sessions};
use slog::{debug, error, info, warn, Drain};
use stamp::{Ssid, StampError, StampMsg, StampMsgBody, StampResponseBodyType, MBZ_VALUE};
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

#[macro_use]
extern crate rocket;

mod custom_handlers;
mod handlers;
mod meta;
mod monitor;
mod ntp;
mod os;
mod parameters;
mod periodicity;
mod responder;
mod server;
mod stamp;
mod tlv;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(default_value_t=IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    ip_addr: IpAddr,

    #[arg(default_value_t = 862)]
    port: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, ValueEnum)]
enum MalformedWhy {
    BadFlags,
    BadLength,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Sender {
        #[arg(long)]
        ssid: Option<u16>,

        #[arg(long)]
        tlv: Option<String>,

        /// Include an unrecognized Tlv in the test packet.
        #[arg(long, default_value_t = false)]
        unrecognized: bool,

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
    },

    Reflector {
        #[arg(
            long,
            default_value_t = false,
            help = "Run teaparty in stateless mode."
        )]
        stateless: bool,

        #[arg(long, action = clap::ArgAction::Append, help = "Specify hearbeat message target and interval (in seconds) as [IP:PORT]@[Seconds]")]
        heartbeat: Vec<HeartbeatConfiguration>,
    },
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

fn client(args: Cli, handlers: Handlers, logger: slog::Logger) -> Result<(), StampError> {
    let server_addr = SocketAddr::new(args.ip_addr, args.port);
    let (
        maybe_ssid,
        maybe_tlv_name,
        unrecognized,
        malformed,
        use_ecn,
        use_dscp,
        src_port,
        authenticated,
    ) = match args.command {
        Commands::Sender {
            ssid,
            tlv,
            unrecognized,
            malformed,
            ecn,
            dscp,
            src_port,
            authenticated,
        } => (
            ssid.map(Ssid::Ssid),
            tlv,
            unrecognized,
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
        tos_byte |= 0x1;
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

        let ecn_argment = TestArgument::Ecn(EcnValue::from(tos_byte));
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
        tos_byte |= Into::<u8>::into(DscpValue::EF);
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

        let dscp_argment = TestArgument::Dscp(DscpValue::from(tos_byte));
        test_arguments.add_argument(parameters::TestArgumentKind::Dscp, dscp_argment);

        info!(
            logger,
            "Done configuring the sending value of the IpV4 DSCP on the server socket."
        );
    }

    let mut tlvs = maybe_tlv_name.map_or(Ok(vec![]), |tlv_name| {
        if let Some(request_tlv) = handlers.get_request(tlv_name.clone(), Some(test_arguments)) {
            Ok(vec![request_tlv])
        } else {
            error!(logger, "Cannot send request for unknown Tlv {}", tlv_name);
            Err(StampError::Other(format!(
                "No Tlv available with name {}",
                tlv_name
            )))
        }
    })?;

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

    if unrecognized {
        tlvs.extend(vec![tlv::Tlv::unrecognized(52)]);
    }

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
        malformed: None,
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

fn server(args: Cli, handlers: Handlers, logger: slog::Logger) -> Result<(), StampError> {
    // The command is specific to the server. The match should *only* yield a
    // server command.
    let (stateless, heartbeats) = match args.command {
        Commands::Reflector {
            stateless,
            heartbeat,
        } => (stateless, heartbeat),
        _ => {
            return Err(StampError::Other(
                "Somehow a non-server command was found during an invocation of the server.".into(),
            ))
        }
    };

    let bind_socket_addr = SocketAddr::from((args.ip_addr, args.port));
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

    info!(
        logger,
        "About to configure the test parameters on the server socket."
    );

    let mut parameters = TestParameters::new();
    let test_argument_space_required = parameters.configure_parameters(&socket, logger.clone())?;
    info!(
        logger,
        "Done configuring the test parameters on the server socket."
    );

    let mut poller = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(128);
    poller
        .registry()
        .register::<mio::unix::SourceFd>(
            &mut mio::unix::SourceFd(&socket.as_raw_fd()),
            Token(0),
            Interest::READABLE,
        )
        .unwrap();

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

    {
        let monitor = Monitor {
            sessions: sessions.clone(),
            periodic: periodical.clone(),
        };
        let logger = logger.clone();
        thread::spawn(move || {
            meta::launch_meta(monitor, logger);
        });
    }

    loop {
        poller.poll(&mut events, None)?;

        for event in events.iter() {
            // We have an event. It's terribly unlikely that it is _not_ for us,
            // but we should check that anyways.
            if event.token() != Token(0) {
                continue;
            }

            // TODO: Dynamically determine MSS
            const MSS: usize = 1500;

            let mut recv_buffer = [0u8; MSS];
            let recv_buffer_iov = IoSliceMut::new(&mut recv_buffer);

            let mut cmsg = vec![0u8; test_argument_space_required];
            let mut iovs = [recv_buffer_iov];

            // Even though we know that there is data waiting, we cannot go after it directly. We still
            // need to lock the socket so that we can be sure we are the only one reading!
            let recv_result = {
                let server_socket = socket.socket.lock().unwrap();

                recvmsg::<SockaddrIn>(
                    server_socket.as_raw_fd(),
                    &mut iovs,
                    Some(&mut cmsg),
                    MsgFlags::empty(),
                )
            };

            if let Err(e) = recv_result {
                // Special case: Don't error if it is EAGAIN
                if e != Errno::EAGAIN {
                    error!(logger, "There was an error on recv msg: {:?}", e);
                }
                continue;
            }

            let recv_data = recv_result.unwrap();

            let arguments = if let Ok(cmsgs) = recv_data.cmsgs() {
                parameters.get_arguments(cmsgs.collect(), logger.clone())
            } else {
                Ok(TestArguments::empty_arguments())
            };

            if let Err(e) = arguments {
                error!(
                    logger,
                    "There was an error getting the test arguments: {}. Abandoning this request.",
                    e
                );
                continue;
            }

            let arguments = arguments.unwrap();

            let client_address = recv_data
                .address
                .map(|f| Into::<SocketAddr>::into((f.ip(), f.port())));

            if client_address.is_none() {
                warn!(
                    logger,
                    "Did not get a client address; not responding to probe."
                );
                continue;
            }
            let client_address = client_address.unwrap();

            let received_time = chrono::Utc::now();

            info!(
                logger,
                "Got a connection from {:?} at {}", client_address, received_time
            );

            {
                let responder = responder.clone();
                let logger = logger.clone();
                let sessions = sessions.clone();
                let recv_msg_size = recv_data.bytes;
                let handlers = handlers.clone();
                let arguments = arguments.clone();
                let server = socket.clone();
                let stamp_packets = recv_buffer[0..recv_msg_size].to_vec();
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

            info!(
                logger,
                "Passed off the connection from {:?} to the handler for handling.", client_address
            );
        }
    }
}

fn main() -> Result<(), StampError> {
    let args = Cli::parse();

    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(slog::Level::Debug)
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!("version" => "0.5"));

    let handlers = CustomHandlers::build();

    match args.command {
        Commands::Reflector {
            stateless: _,
            heartbeat: _,
        } => server(args, handlers, logger),
        Commands::Sender {
            ssid: _,
            tlv: _,
            unrecognized: _,
            malformed: _,
            ecn: _,
            dscp: _,
            src_port: _,
            authenticated: _,
        } => client(args, handlers, logger),
    }
}
