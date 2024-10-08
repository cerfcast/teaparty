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

use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::Mutex;

use nix::sys::socket::sockopt::Ipv4Tos;
use nix::sys::socket::SetSockOpt;
use nix::sys::socket::SockaddrIn;
use slog::Logger;
use slog::{debug, error, info};

use crate::ntp;
use crate::parameters::DscpValue;
use crate::parameters::EcnValue;
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
    fn request(&self) -> Tlv;

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

#[derive(Clone)]
pub struct Handlers {
    handlers: Vec<Arc<Mutex<dyn TlvHandler + Send>>>,
}

impl Handlers {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn add(&mut self, handler: Arc<Mutex<dyn TlvHandler + Send>>) {
        self.handlers.push(handler)
    }

    pub fn get_handler(&self, tlv_id: u8) -> Option<Arc<Mutex<dyn TlvHandler + Send>>> {
        self.handlers
            .iter()
            .find(|e| e.lock().unwrap().tlv_type() == tlv_id)
            .cloned()
    }

    pub fn get_request(&self, tlv_name: String) -> Option<Tlv> {
        self.handlers
            .iter()
            .find(|v| tlv_name == v.lock().unwrap().tlv_name())
            .map(|h| h.lock().unwrap().request())
    }
}

#[allow(clippy::complexity)]
pub async fn handler(
    received_time: chrono::DateTime<chrono::Utc>,
    msg: &[u8],
    test_arguments: TestArguments,
    session: Session,
    sessions: Arc<Sessions>,
    stateful: bool,
    handlers: Handlers,
    responder: Arc<responder::Responder>,
    server: ServerSocket,
    logger: slog::Logger,
) {
    debug!(
        logger,
        "Handling a message of size {} bytes with contents: {:x?}",
        msg.len(),
        msg
    );

    let maybe_stamp_msg = TryInto::<StampMsg>::try_into(msg);

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

    let src_stamp_msg = maybe_stamp_msg.unwrap();

    let mut session_data = SessionData::new();
    session_data.sequence = src_stamp_msg.sequence;
    if stateful {
        let mut sessions = sessions.sessions.lock().unwrap();
        if let Some(existing_session) = sessions.get_mut(&session.clone()) {
            existing_session.sequence += 1;
            session_data = existing_session.clone();
            info!(
                logger,
                "Updated an existing session: {:?}: {:?} (Note: Values printed in network order).",
                session,
                session_data
            );
        } else {
            sessions.insert(session.clone(), SessionData::default());
            session_data = SessionData::default();
            info!(
                logger,
                "Created a new session: {:?}: {:?} (Note: Values printed in network order).",
                session,
                session_data
            );
        }
    }

    let mut tlv_response = Vec::<Tlv>::new();
    for tlv in src_stamp_msg.tlvs {
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
        }
    }

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
        }),
        tlvs: tlv_response,
    };

    let mut response_src_socket_addr = session.src.clone();

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

    let response_result = {
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

pub struct DscpEcnTlv {}

impl TlvHandler for DscpEcnTlv {
    fn tlv_type(&self) -> u8 {
        179
    }

    fn tlv_name(&self) -> String {
        "dscpecn".into()
    }

    fn request(&self) -> Tlv {
        Tlv {
            flags: 0,
            tpe: self.tlv_type(),
            length: 4,
            value: vec![(0x2e << 2) | 1u8, 0, 0, 0],
        }
    }

    fn handle(
        &self,
        _tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am in the Ecn TLV handler!");

        let ecn_argument: u8 = _parameters.get_parameter_value(TestArgumentKind::Ecn)?;
        let dscp_argument: u8 = _parameters.get_parameter_value(TestArgumentKind::Dscp)?;

        info!(logger, "Got ecn argument: {:x}", ecn_argument);
        info!(logger, "Got dscp argument: {:x}", dscp_argument);

        let dscp_ecn_response = (dscp_argument << 2) | ecn_argument;

        let ecn_requested_response: EcnValue = (_tlv.value[0] & 0x3).into();
        let dscp_requested_response: DscpValue = (_tlv.value[0] & 0xfc).into();

        info!(logger, "Ecn requested back? {:?}", ecn_requested_response);
        info!(logger, "Dscp requested back? {:?}", dscp_requested_response);

        let response = Tlv {
            flags: 0,
            tpe: self.tlv_type(),
            length: 4,
            value: vec![_tlv.value[0], dscp_ecn_response, 0, 0],
        };
        Ok(response)
    }

    fn prepare_response_target(
        &self,
        _: &mut StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn {
        info!(logger, "Preparing the response target in the Dscp Ecn Tlv.");
        address
    }

    fn prepare_response_socket(
        &self,
        response: &mut StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Preparing the response socket in the Dscp Ecn Tlv.");

        for tlv in response.tlvs.iter_mut() {
            if tlv.tpe == self.tlv_type() {
                let set_tos_value = tlv.value[0] as i32;
                if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_tos_value) {
                    error!(
                        logger,
                        "There was an error preparing the response socket: {}", set_tos_value_err
                    );
                    // This is not an error. All that we need to do is make sure that the RP
                    // field is set to 1 to indicate that we were not allowed to assign
                    // the requested DSCP/ECN values to the socket.
                }
                tlv.value[2] = 0x80;
                return Ok(());
            }
        }
        Ok(())
    }

    fn unprepare_response_socket(
        &self,
        _: &StampMsg,
        socket: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "Unpreparing the response socket in the Dscp Ecn Tlv."
        );
        let set_tos_value = 0i32;
        if let Err(set_tos_value_err) = Ipv4Tos.set(&socket, &set_tos_value) {
            error!(
                logger,
                "There was an error unpreparing the response socket: {}", set_tos_value_err
            );
            return Err(Into::<StampError>::into(Into::<std::io::Error>::into(
                std::io::ErrorKind::ConnectionRefused,
            )));
        }
        Ok(())
    }
}

pub struct TimeTlv {}

impl TlvHandler for TimeTlv {
    fn tlv_type(&self) -> u8 {
        0x3
    }

    fn tlv_name(&self) -> String {
        "timestamp".into()
    }

    fn request(&self) -> Tlv {
        Tlv {
            flags: 0,
            tpe: 0x3,
            length: 4,
            value: vec![0u8; 4],
        }
    }

    fn handle(
        &self,
        _tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am handling a timestamp Tlv.");
        let mut response_data = [0u8; 4];
        response_data[0] = 1; // NTP
        response_data[1] = 2; // Software local
        response_data[2] = 1; // NTP
        response_data[3] = 2; // Software local
        let response = Tlv {
            flags: 0,
            tpe: 0x3,
            length: 4,
            value: response_data.to_vec(),
        };
        Ok(response)
    }

    fn prepare_response_target(
        &self,
        _: &mut StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn {
        info!(
            logger,
            "Preparing the response target in the Timestamp Tlv."
        );
        address
    }

    fn prepare_response_socket(
        &self,
        _: &mut StampMsg,
        _: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(
            logger,
            "Preparing the response socket in the Timestamp Tlv."
        );
        Ok(())
    }

    fn unprepare_response_socket(
        &self,
        _: &StampMsg,
        _: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Unpreparing the response socket in the Time Tlv.");
        Ok(())
    }
}

pub struct DestinationPort {}

impl TlvHandler for DestinationPort {
    fn tlv_type(&self) -> u8 {
        177
    }

    fn tlv_name(&self) -> String {
        "destinationport".into()
    }

    fn request(&self) -> Tlv {
        let mut data = [0u8; 4];

        data[0..2].copy_from_slice(&983u16.to_be_bytes());

        Tlv {
            flags: 0,
            tpe: 177,
            length: 4,
            value: data.to_vec(),
        }
    }

    fn handle(
        &self,
        _tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, StampError> {
        info!(logger, "I am handling a destination port Tlv.");
        Ok(_tlv.clone())
    }

    fn prepare_response_target(
        &self,
        response: &mut StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn {
        info!(
            logger,
            "Preparing the response target in the destination port Tlv."
        );
        for tlv in response.tlvs.iter() {
            if tlv.tpe == self.tlv_type() {
                let new_port: u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                let mut ipv4: SocketAddrV4 = address.into();
                ipv4.set_port(new_port);
                return ipv4.into();
            }
        }
        address
    }

    fn prepare_response_socket(
        &self,
        _: &mut StampMsg,
        _: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Preparing the response socket in the Time Tlv.");
        Ok(())
    }

    fn unprepare_response_socket(
        &self,
        _: &StampMsg,
        _: &UdpSocket,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Unpreparing the response socket in the Time Tlv.");
        Ok(())
    }
}
