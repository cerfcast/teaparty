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

use nix::sys::socket::SockaddrIn;
use slog::Logger;
use slog::{debug, error, info};

use crate::ntp;
use crate::parameters::TestArgumentKind;
use crate::parameters::TestArguments;
use crate::responder;
use crate::server::Session;
use crate::server::SessionData;
use crate::server::Sessions;
use crate::stamp::StampError;
use crate::stamp::StampMsg;
use crate::stamp::StampMsgBody;
use crate::stamp::StampResponseContents;
use crate::tlv;
use crate::tlv::Tlv;

pub trait TlvHandler {
    fn tlv_type(&self) -> u8;
    fn handle(
        &self,
        tlv: &tlv::Tlv,
        parameters: &TestArguments,
        client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, std::io::Error>;
    fn tlv_name(&self) -> String;
    fn request(&self) -> Tlv;
    fn prepare_response_target(
        &self,
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn;
    fn prepare_response_socket(
        &self,
        response: &StampMsg,
        address: SockaddrIn,
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

    let response_stamp_msg = StampMsg {
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
            received_ttl: test_arguments.get_parameter_value(TestArgumentKind::Ttl),
            mbz_2: Default::default(),
        }),
        tlvs: tlv_response,
    };

    let mut response_src_socket_addr = session.src.clone();

    for response_tlv in response_stamp_msg.tlvs.iter() {
        if let Some(response_tlv_handler) = handlers.get_handler(response_tlv.tpe) {
            response_src_socket_addr = response_tlv_handler
                .lock()
                .unwrap()
                .prepare_response_target(
                    &response_stamp_msg,
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

    info!(
        logger,
        "Responding with stamp msg: {:?}", response_stamp_msg
    );
    let response_result = responder.write(
        &Into::<Vec<u8>>::into(response_stamp_msg),
        response_src_socket,
        session.dst,
    );

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
            value: vec![0u8; 4],
        }
    }

    fn handle(
        &self,
        _tlv: &tlv::Tlv,
        _parameters: &TestArguments,
        _client: SockaddrIn,
        logger: slog::Logger,
    ) -> Result<Tlv, std::io::Error> {
        info!(logger, "I am in the Ecn TLV handler!");
        let response = Tlv {
            flags: 0,
            tpe: 0,
            length: 5,
            value: vec![0u8; 5],
        };
        Ok(response)
    }

    fn prepare_response_target(
        &self,
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn {
        info!(logger, "Preparing the response target in the Dscp Ecn Tlv.");
        address
    }

    fn prepare_response_socket(
        &self,
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Preparing the response socket in the Dscp Ecn Tlv.");
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
    ) -> Result<Tlv, std::io::Error> {
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
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> SockaddrIn {
        info!(logger, "Preparing the response target in the Time Tlv.");
        address
    }

    fn prepare_response_socket(
        &self,
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Preparing the response socket in the Time Tlv.");
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
    ) -> Result<Tlv, std::io::Error> {
        info!(logger, "I am handling a destination port Tlv.");
        Ok(_tlv.clone())
    }

    fn prepare_response_target(
        &self,
        response: &StampMsg,
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
        response: &StampMsg,
        address: SockaddrIn,
        logger: Logger,
    ) -> Result<(), StampError> {
        info!(logger, "Preparing the response socket in the Time Tlv.");
        Ok(())
    }
}
