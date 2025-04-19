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

use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;

use clap::ArgMatches;
use clap::Command;
use slog::Logger;
use slog::{debug, error, info, warn};

use crate::asymmetry::Asymmetry;
use crate::netconf::NetConfiguration;
use crate::netconf::NetConfigurationItem;
use crate::ntp;
use crate::parameters::TestArgumentKind;
use crate::parameters::TestArguments;
use crate::responder;
use crate::responder::Responder;
use crate::server::ServerSocket;
use crate::server::Session;
use crate::server::SessionData;
use crate::server::SessionHistoryEntry;
use crate::server::Sessions;
use crate::stamp::StampError;
use crate::stamp::StampMsg;
use crate::stamp::StampMsgBody;
use crate::stamp::StampResponseBody;
use crate::stamp::StampSendBodyType;
use crate::tlv;
use crate::tlv::Tlv;
use crate::tlv::Tlvs;

pub type TlvRequestResult = Option<(Tlv, Option<String>)>;

#[derive(Debug, Clone)]
pub enum HandlerError {
    MissingRawSize,
}

/// An object that participates in handling STAMP messages
/// with certain TLVs.
///
/// When a test packet is received ...
/// 1. Every registered TlvHandler's [`TlvHandler::handle`] method
///    will be called.
/// 2. After the response packet is generated, every registered TlvHandler's
///    [`TlvHandler::prepare_response_target`] method will be called so that
///    every handler has the chance to change the destination IP/port of the
///    reflected packet.
/// 3. After the destination IP/port of the reflected packet is confirmed,
///    every registered TlvHandler's [`TlvHandler::prepare_response_socket`]
///    method is called so that every handler has the chance to change any
///    socket configuration necessary to generate a (semantically) correct
///    response.
/// 4. After the reflected test packet is sent, every registered TlvHandler's
///    [`TlvHandler::unprepare_response_socket`] method is called so that
///    socket used to send the response can be returned to its original state.
/// > **NOTE**: [`TlvHandler::prepare_response_socket`] and
/// > `TlvHandler::unprepare_response_socket`] must work together to leave
/// > the socket unchanged with respect to its configuration before it was
/// > first [`TlvHandler::prepare_response_socket`]'d by this handler.
pub trait TlvHandler {
    /// The name of the TLV.
    fn tlv_name(&self) -> String;

    fn tlv_cli_command(&self, command: Command) -> Command;

    /// The type of the TLV for which this object will respond.
    fn tlv_type(&self) -> u8;

    /// Modify a STAMP test packet before it is subjected to normal
    /// TLV handling.
    #[allow(unused_variables)]
    fn request_fixup(
        &self,
        request: &mut StampMsg,
        session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError> {
        Ok(())
    }

    /// The means of generating a TLV that goes into a STAMP reflector
    /// packet for a received STAMP packet with type that matches [`TlvHandler::tlv_type`].
    fn handle(
        &self,
        tlv: &tlv::Tlv,
        parameters: &TestArguments,
        netconfig: &mut NetConfiguration,
        client: SocketAddr,
        session: &mut Option<SessionData>,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError>;

    /// Generate a TLV to include a STAMP test packet.
    fn request(
        &self,
        arguments: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> TlvRequestResult;

    /// Customize the IP/port of the destination of the reflected STAMP packet.
    ///
    /// This method generates a (possibly) modified [`address`]. Return [`address`]
    /// if there is no change necessary.
    fn prepare_response_target(
        &self,
        response: &mut StampMsg,
        address: SocketAddr,
        logger: Logger,
    ) -> SocketAddr;

    /// Do final fixup of STAMP message before it is transmitted.
    fn pre_send_fixup(
        &self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        session: &Option<SessionData>,
        logger: Logger,
    ) -> Result<(), StampError>;

    /// Handle any errors that resulted from a failure to apply requested netconfig
    /// to response.
    ///
    /// `item` is the netconfig that could not be applied.
    fn handle_netconfig_error(
        &self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        item: NetConfigurationItem,
        logger: Logger,
    );

    /// Startup any asymmetric processing resulting from STAMP test packet.
    ///
    /// If any asymmetric processing is required, this function can handle the
    /// creation of that processing by referring to `runtime`, among others.
    #[allow(unused_variables, clippy::too_many_arguments)]
    fn handle_asymmetry(
        &self,
        response: StampMsg,
        sessions: Option<Sessions>,
        base_destination: SocketAddr,
        base_src: SocketAddr,
        responder: Arc<Responder>,
        runtime: Arc<Asymmetry<()>>,
        logger: Logger,
    ) -> Result<(), StampError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Handlers {
    handlers: Vec<Arc<Mutex<dyn TlvHandler + Send>>>,
}

impl Handlers {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Add a Tlv handler to the list of available handlers.
    pub fn add(&mut self, handler: Arc<Mutex<dyn TlvHandler + Send>>) {
        self.handlers.push(handler)
    }

    /// Given a Tlv type value, find a handler, if one is available.
    pub fn get_handler(&self, tlv_id: u8) -> Option<Arc<Mutex<dyn TlvHandler + Send>>> {
        self.handlers
            .iter()
            .find(|e| {
                let handler_type = e.lock().unwrap().tlv_type();
                handler_type != 0 && handler_type == tlv_id
            })
            .cloned()
    }

    pub fn get_cli_commands(&self) -> Command {
        let command = Command::new("tlvs").no_binary_name(true);
        self.handlers
            .iter()
            .fold(command, |e, tlv| tlv.lock().unwrap().tlv_cli_command(e))
    }

    pub fn get_requests(
        &self,
        args: Option<TestArguments>,
        matches: &mut ArgMatches,
    ) -> Option<Tlvs> {
        let matches = matches.subcommand_matches("sender")?;
        let matches = matches.subcommand_matches("tlvs")?;

        let mut tlvs = Tlvs::new();

        let mut matches = matches.clone();
        loop {
            let command = self
                .handlers
                .iter()
                .find_map(|h| h.lock().unwrap().request(args.clone(), &mut matches));

            if let Some((tlv, _)) = &command {
                tlvs.add_tlv(tlv.clone()).ok()?;
            }

            let next_tlv_command = if let Some((_, Some(remainder))) = command {
                remainder
            } else {
                break;
            };

            matches = self
                .get_cli_commands()
                .get_matches_from(next_tlv_command.split(" "));
        }
        Some(tlvs)
    }
}

#[allow(clippy::complexity)]
pub fn handler(
    received_time: chrono::DateTime<chrono::Utc>,
    msg: &Vec<u8>,
    test_arguments: TestArguments,
    sessions: Option<Sessions>,
    handlers: Handlers,
    responder: Arc<responder::Responder>,
    server: ServerSocket,
    client_address: SocketAddr,
    runtime: Arc<Asymmetry<()>>,
    logger: slog::Logger,
) {
    debug!(
        logger,
        "Handling a message of size {} bytes with contents: {:x?}",
        msg.len(),
        msg
    );

    let maybe_stamp_msg = TryInto::<StampMsg>::try_into(msg.as_slice());

    if maybe_stamp_msg.is_err() {
        error!(
            logger,
            "Incoming message is not a stamp message: {:?}",
            maybe_stamp_msg.unwrap_err()
        );
        return;
    }

    debug!(
        logger,
        "The following arguments are available for this test:\n {:?}", test_arguments
    );

    let (mut src_stamp_msg, client_authenticated) = match maybe_stamp_msg.as_ref().unwrap().body {
        StampMsgBody::Send(StampSendBodyType::Authenticated(_)) => (maybe_stamp_msg.unwrap(), true),
        StampMsgBody::Send(StampSendBodyType::UnAuthenticated(_)) => {
            (maybe_stamp_msg.unwrap(), false)
        }
        _ => {
            error!(logger, "Incoming message is not a stamp send message",);
            return;
        }
    };

    info!(
        logger,
        "Handling a{} STAMP packet: {:?}",
        if client_authenticated {
            "n authenticated".to_string()
        } else {
            "".to_string()
        },
        src_stamp_msg
    );

    let server_address = if let SocketAddr::V4(v4) = server.socket_addr {
        v4
    } else {
        panic!("Ipv6 not supported yet.")
    };

    let session = Session::new(
        client_address.into(),
        server_address.into(),
        src_stamp_msg.ssid.clone(),
    );

    let mut netconfig = NetConfiguration::new();

    let response_stamp_msg = {
        // Lock the sessions while we handle!
        let mut session_data = if let Some(sessions) = sessions.as_ref() {
            let mut sessions = sessions.sessions.lock().unwrap();
            if let Some(existing_session) = sessions.get_mut(&session.clone()) {
                existing_session.sequence += 1;
                existing_session.last = std::time::SystemTime::now();

                let existing_session = existing_session.clone();
                info!(
                logger,
                "Updated an existing session: {:?}: {:?} (Note: Values printed in network order).",
                session,
                existing_session
            );
                Some(existing_session)
            } else {
                let mut new_session = SessionData::new(5);
                new_session.sequence = src_stamp_msg.sequence + 1;
                sessions.insert(session.clone(), new_session.clone());
                info!(
                    logger,
                    "Created a new session: {:?}: {:?} (Note: Values printed in network order).",
                    session,
                    new_session
                );
                Some(new_session)
            }
        } else {
            None
        };

        let keymat = session_data.as_ref().and_then(|sd| sd.key.clone());
        let authentication_result = if client_authenticated {
            match src_stamp_msg.authenticate(&keymat) {
                Ok(checked_hash) => {
                    if checked_hash == src_stamp_msg.hmac {
                        Ok(())
                    } else {
                        info!(
                            logger,
                            "Wanted HMAC {:x?} and got HMAC {:?} (used {:x?} for keymat)",
                            checked_hash,
                            src_stamp_msg.hmac,
                            keymat
                        );
                        Err(StampError::InvalidSignature)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        };

        if let Err(e) = authentication_result {
            warn!(
                logger,
                "An authenticated packet arrived which could not be validated: {}", e
            );
            return;
        }

        for handler in handlers.handlers.iter() {
            let handler = handler.lock().unwrap();
            if let Err(err) =
                handler.request_fixup(&mut src_stamp_msg, &session_data, logger.clone())
            {
                error!(logger, "Abandoning Tlv processing because the {} handler produced an error in its request fixup: {}", handler.tlv_name(), err);
                return;
            }
        }

        // Let each of the Tlv handlers have a chance to generate a Tlv response for any Tlvs in the session-sender
        // test packet. The only Tlvs left in the tlvs array are valid (after the earlier check).
        let mut tlv_response = src_stamp_msg.tlvs.clone();
        for tlv in &mut tlv_response.iter_mut() {
            if !tlv.is_valid_request() {
                error!(
                    logger.clone(),
                    "Abandoning Tlv processing because a Tlv's flags contained the malformed flag."
                );
                break;
            }

            let handler = handlers.get_handler(tlv.tpe);
            if let Some(handler) = handler {
                let locked_handler = handler.lock().unwrap();
                let handler_result = locked_handler.handle(
                    tlv,
                    &test_arguments,
                    &mut netconfig,
                    session.src,
                    &mut session_data,
                    logger.clone(),
                );

                match handler_result {
                    Ok(o) => {
                        *tlv = o;
                    }
                    Err(StampError::MalformedTlv(e)) => {
                        info!(logger, "{} set a TLV as malformed because {:?}; abandoning processing of further Tlvs", locked_handler.tlv_name(), e);
                        tlv.flags.set_malformed(true);
                        break;
                    }
                    Err(e) => {
                        // TODO: Check
                        error!(logger, "There was an unrecognized error from the Tlv-specific handler {}: {}. No response will be generated.", locked_handler.tlv_name(), e);
                    }
                }
            } else {
                // No handler found, make sure that we copy in the Tlv and mark it as unrecognized.
                error!(
                    logger,
                    "There was no tlv-specific handler found for tlv with type 0x{:x?}.", tlv.tpe
                );
                tlv.flags.set_unrecognized(true);
            }
        }

        // It's possible that one of the Tlvs does not have their flags set correctly. If that
        // is the case, then we need to make some adjustments.
        tlv_response.handle_malformed_response();

        let body = StampResponseBody {
            received_time: received_time.into(),
            sent_sequence: src_stamp_msg.sequence,
            sent_time: src_stamp_msg.time.clone(),
            sent_error: src_stamp_msg.error,
            received_ttl: test_arguments
                .get_parameter_value(TestArgumentKind::Ttl)
                .unwrap(),
        };

        // Generate a session-reflector test packet based on the Tlvs generated by the handlers.
        let mut response_stamp_msg = StampMsg {
            time: ntp::NtpTime::now(),
            sequence: session_data
                .as_ref()
                .map_or(src_stamp_msg.sequence, |sd| sd.sequence),
            error: Default::default(),
            ssid: src_stamp_msg.ssid,
            body: if client_authenticated {
                StampMsgBody::Response(crate::stamp::StampResponseBodyType::Authenticated(body))
            } else {
                StampMsgBody::Response(crate::stamp::StampResponseBodyType::UnAuthenticated(body))
            },
            hmac: None,
            tlvs: tlv_response,
            raw_length: None,
        };

        if client_authenticated {
            match response_stamp_msg.authenticate(&session_data.and_then(|sd| sd.key)) {
                Ok(key) => response_stamp_msg.hmac = key,
                Err(e) => {
                    error!(logger, "Failed to authenticate the response packet: {}", e);
                    return;
                }
            }
        }

        // We no longer need exclusive access to the session information.
        response_stamp_msg
    };

    // src and dest are "backward": They are from the perspective of the session sender!
    responder.respond(
        response_stamp_msg.clone(),
        netconfig,
        session.dst.clone(),
        session.src.clone(),
    );

    // Update the session with the information about the response that we just wrote!
    if let Some(sessions) = sessions.as_ref() {
        if let Some(existing_session) = sessions.sessions.lock().unwrap().get_mut(&session.clone())
        {
            let entry = SessionHistoryEntry {
                received_time: received_time.into(),
                sender_time: src_stamp_msg.time,
                sent_time: response_stamp_msg.time.clone(),
                sender_sequence: src_stamp_msg.sequence,
                sequence: response_stamp_msg.sequence,
            };
            existing_session.history.add(entry);
        } else {
            unreachable!("The server is stateful -- we must have a session at this point.")
        }
    }

    // Give each handler the chance to start some asymmetric processing.
    for response_tlv in response_stamp_msg.tlvs.tlvs.clone().iter() {
        if let Some(response_tlv_handler) = handlers.get_handler(response_tlv.tpe) {
            // Notice that the lock use is in a scope!
            let handler_name = { response_tlv_handler.lock().unwrap().tlv_name() };
            if let Err(e) = response_tlv_handler.lock().unwrap().handle_asymmetry(
                response_stamp_msg.clone(),
                sessions.clone(),
                session.src.clone(),
                session.dst.clone(),
                responder.clone(),
                runtime.clone(),
                logger.clone(),
            ) {
                error!(
                    logger,
                    "Error starting asymmetric response handling for TLV {}: {}.", handler_name, e
                );
            }
        }
    }
}
