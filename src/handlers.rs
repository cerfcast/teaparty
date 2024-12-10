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

use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;

use nix::sys::socket::SockaddrIn;
use slog::Logger;
use slog::{debug, error, info, warn};

use crate::ntp;
use crate::parameters::TestArgumentKind;
use crate::parameters::TestArguments;
use crate::responder;
use crate::server::ServerSocket;
use crate::server::Session;
use crate::server::SessionData;
use crate::server::Sessions;
use crate::stamp::StampError;
use crate::stamp::StampMsg;
use crate::stamp::StampMsgBody;
use crate::stamp::StampResponseContents;
use crate::tlv;
use crate::tlv::Tlv;

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
    /// The type of the TLV for which this object will respond.
    fn tlv_type(&self) -> u8;

    /// The means of generating a TLV that goes into a STAMP reflector
    /// packet for a received STAMP packet with type that matches [`TlvHandler::tlv_type`].
    fn handle(
        &self,
        tlv: &tlv::Tlv,
        parameters: &TestArguments,
        client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError>;

    /// The name of this TLV.
    ///
    /// The value returned from this method will be used to enable the
    /// user to include one of these TLVs in a test packet when the
    /// application is run in client mode.
    fn tlv_name(&self) -> String;

    /// Generate a TLV to include a STAMP test packet.
    fn request(&self, arguments: Option<TestArguments>) -> Tlv;

    /// Customize the IP/port of the destination of the reflected STAMP packet.
    ///
    /// This method generates a (possibly) modified [`address`]. Return [`address`]
    /// if there is no change necessary.
    fn prepare_response_target(
        &self,
        response: &mut StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn;

    /// Customize the socket used to send the reflected STAMP packet.
    ///
    /// [`TlvHandler::unprepare_response_socket`] and this method are called in
    /// pairs. See documentation for that method for more information.
    fn prepare_response_socket(
        &self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError>;

    /// Undo any previously made customizations to the socket used to
    /// send the reflected STAMP packet.
    ///
    /// [`TlvHandler::prepare_response_socket`] and this method are called in
    /// pairs and should leave the socket in the same configuration as
    /// it was before [`TlvHandler::prepare_response_socket`].
    fn unprepare_response_socket(
        &self,
        response: &StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError>;
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
            .find(|e| e.lock().unwrap().tlv_type() == tlv_id)
            .cloned()
    }

    /// Given the name of a Tlv, find a request, if one is available.
    pub fn get_request(&self, tlv_name: String, args: Option<TestArguments>) -> Option<Tlv> {
        self.handlers
            .iter()
            .find(|v| tlv_name == v.lock().unwrap().tlv_name())
            .map(|h| h.lock().unwrap().request(args))
    }
}

#[allow(clippy::complexity)]
pub fn handler(
    received_time: chrono::DateTime<chrono::Utc>,
    msg: &Vec<u8>,
    test_arguments: TestArguments,
    sessions: Sessions,
    stateful: bool,
    handlers: Handlers,
    responder: Arc<responder::Responder>,
    server: ServerSocket,
    client_address: SockaddrIn,
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

    let mut src_stamp_msg = maybe_stamp_msg.unwrap();

    let server_address = if let SocketAddr::V4(v4) = server.socket_addr {
        v4
    } else {
        panic!("Ipv6 not supported yet.")
    };

    let session = Session::new(
        Into::<SockaddrIn>::into(server_address),
        client_address,
        src_stamp_msg.ssid.clone(),
    );
    let mut session_data = SessionData::new();
    session_data.sequence = src_stamp_msg.sequence;

    if stateful {
        let mut sessions = sessions.sessions.lock().unwrap();
        if let Some(existing_session) = sessions.get_mut(&session.clone()) {

            existing_session.sequence += 1;
            existing_session.last = std::time::SystemTime::now();

            session_data = existing_session.clone();
            info!(
                logger,
                "Updated an existing session: {:?}: {:?} (Note: Values printed in network order).",
                session,
                session_data
            );
        } else {
            let new_session = SessionData::new();
            sessions.insert(session.clone(), new_session.clone());
            info!(
                logger,
                "Created a new session: {:?}: {:?} (Note: Values printed in network order).",
                session,
                new_session
            );
        }
    }

    // It's possible that one of the Tlvs does not have their flags set correctly. If that
    // is the case, then we need to make some adjustments.

    src_stamp_msg.handle_invalid_tlv_request_flags();

    // Let each of the Tlv handlers have a chance to generate a Tlv response for any Tlvs in the session-sender
    // test packet.
    let mut tlv_response: Vec<tlv::Tlv> = vec![];
    for mut tlv in src_stamp_msg.tlvs {
        let handler = handlers.get_handler(tlv.tpe);
        if let Some(handler) = handler {
            let handler_result =
                handler
                    .lock()
                    .unwrap()
                    .handle(&tlv, &test_arguments, session.dst, logger.clone());
            if let Err(e) = handler_result {
                error!(logger, "There was an error from the tlv-specific handler: {}. No response will be generated.", e);
                return;
            }
            tlv_response.push(handler_result.unwrap());
        } else {
            // No handler found, make sure that we copy in the Tlv and mark it as unrecognized.
            error!(logger, "There was no tlv-specific handler found for tlv with type 0x{:x?}.", tlv.tpe);
            tlv.flags.set_unrecognized(true);
            tlv_response.push(tlv);
        }
    }

    // Generate a session-reflector test packet based on the Tlvs generated by the handlers.
    let mut response_stamp_msg = StampMsg {
        time: ntp::NtpTime::now(),
        sequence: session_data.sequence,
        error: Default::default(),
        ssid: src_stamp_msg.ssid,
        body: StampMsgBody::Response(StampResponseContents {
            received_time: received_time.into(),
            sent_sequence: src_stamp_msg.sequence,
            sent_time: src_stamp_msg.time,
            sent_error: src_stamp_msg.error,
            mbz_1: Default::default(),
            received_ttl: test_arguments
                .get_parameter_value(TestArgumentKind::Ttl)
                .unwrap(),
            mbz_2: Default::default(),
            authenticated: false,
        }),
        hmac: None,
        tlvs: tlv_response,
        // Copy any malformed Tlvs into the packet sent back.
        malformed: src_stamp_msg.malformed,
    };

    let mut response_src_socket_addr = session.src.clone();

    // Let each of the handlers have the chance to modify the socket from which the response will be sent.
    for response_tlv in response_stamp_msg.tlvs.clone().iter() {
        if let Some(response_tlv_handler) = handlers.get_handler(response_tlv.tpe) {
            response_src_socket_addr = response_tlv_handler
                .lock()
                .unwrap()
                .prepare_response_target(
                    &mut response_stamp_msg,
                    response_src_socket_addr,
                    logger.clone(),
                );
        }
    }

    // If there was a change requested, handle that request now.
    let response_src_socket = if response_src_socket_addr != session.src {
        let response_src_socket = UdpSocket::bind((
            response_src_socket_addr.ip(),
            response_src_socket_addr.port(),
        ));

        info!(
            logger,
            "A handler wanted to change the response's source to {}", response_src_socket_addr
        );

        if let Err(e) = response_src_socket {
            error!(
                logger,
                "There was an error binding the response source socket: {}. Abandoning response.",
                e
            );
            return;
        }

        Some(response_src_socket.unwrap())
    } else {
        None
    };

    // It's possible that the handlers also want to add some special configuration to the socket, too.
    let response_result = {
        // Take a lock on the socket that we are going to use to send the response packet. We do this locking
        // because the handlers may want to make a change to the socket's configuration and attempting to
        // read packets in this configuration could cause a problem.
        let unlocked_socket_to_prepare = response_src_socket
            .map(|s| Arc::new(Mutex::new(s)))
            .or(Some(server.socket.clone()))
            .unwrap();

        let locked_socket_to_prepare = unlocked_socket_to_prepare.lock().unwrap();

        for response_tlv in response_stamp_msg.tlvs.clone().iter() {
            if let Some(response_tlv_handler) = handlers.get_handler(response_tlv.tpe) {
                if let Err(e) = response_tlv_handler
                    .lock()
                    .unwrap()
                    .prepare_response_socket(
                        &mut response_stamp_msg,
                        &locked_socket_to_prepare,
                        logger.clone(),
                    )
                {
                    error!(logger, "There was an error preparing the response socket: {}. Abandoning response.", e);
                    return;
                }
            }
        }

        info!(
            logger,
            "Responding with stamp msg: {:?}", response_stamp_msg
        );

        let write_result = responder.write(
            &Into::<Vec<u8>>::into(response_stamp_msg.clone()),
            &locked_socket_to_prepare,
            session.dst,
        );

        // If the handlers changed the socket in some way, they are responsible for setting it back!
        for response_tlv in response_stamp_msg.tlvs.iter() {
            if let Some(response_tlv_handler) = handlers.get_handler(response_tlv.tpe) {
                if let Err(e) = response_tlv_handler
                    .lock()
                    .unwrap()
                    .unprepare_response_socket(
                        &response_stamp_msg,
                        &locked_socket_to_prepare,
                        logger.clone(),
                    )
                {
                    error!(
                        logger,
                        "There was an error unpreparing the response socket: {}. Danger.", e
                    );
                    return;
                }
            }
        }

        write_result
    };

    if response_result.is_err() {
        error!(
            logger,
            "An error occurred sending the response: {}",
            response_result.unwrap_err()
        );
        return;
    }

    info!(
        logger,
        "Sent {} bytes as a response.",
        response_result.unwrap()
    );
}
