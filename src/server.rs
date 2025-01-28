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

use std::{
    collections::HashMap,
    fmt::Debug,
    net::{self, SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
};

use crate::{ntp, stamp::Ssid};
use serde::{ser::SerializeStruct, Serialize};

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct SessionHistoryEntry {
    pub sequence: u32,
    pub sender_sequence: u32,
    pub received_time: ntp::NtpTime,
    pub sender_time: ntp::NtpTime,
    pub sent_time: ntp::NtpTime,
}

impl From<SessionHistoryEntry> for Vec<u8> {
    fn from(value: SessionHistoryEntry) -> Self {
        let mut result: Vec<u8> = vec![];
        result.extend_from_slice(&u32::to_be_bytes(value.sequence));
        result.extend_from_slice(&u32::to_be_bytes(value.sender_sequence));
        result.extend(Into::<Vec<u8>>::into(value.received_time));
        result.extend(Into::<Vec<u8>>::into(value.sender_time));
        result.extend(Into::<Vec<u8>>::into(value.sent_time));
        result
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionHistory {
    history: Vec<Option<SessionHistoryEntry>>,
    latest: Option<usize>,
}

impl SessionHistory {
    pub fn new(size: usize) -> Self {
        let history: Vec<Option<SessionHistoryEntry>> = vec![None; size];
        SessionHistory {
            history,
            latest: None,
        }
    }

    pub fn add(&mut self, entry: SessionHistoryEntry) {
        self.latest = match self.latest {
            None => Some(0),
            Some(previous) => Some((previous + 1) % self.history.len()),
        };
        let latest = self.latest.unwrap();
        self.history[latest] = Some(entry);
    }
}

impl From<SessionHistory> for Vec<u8> {
    fn from(value: SessionHistory) -> Self {
        let mut result: Vec<u8> = vec![];
        let mut current = value.latest.unwrap_or(0);
        let mut history_entries = 0;

        // As long as there are _some_ history events, let's vec-torize them.
        while let Some(entry) = &value.history[current] {
            result.extend(Into::<Vec<u8>>::into(entry.clone()));
            current = if current == 0 {
                value.history.len() - 1
            } else {
                current - 1
            };
            history_entries += 1;

            // If we have added all the entries, let's stop.
            if history_entries == value.history.len() {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod session_history_tests {
    use crate::ntp;

    use super::{SessionHistory, SessionHistoryEntry};

    #[test]
    fn simple_history_test_leftover_space() {
        let mut session_history = SessionHistory::new(2);
        let entry = SessionHistoryEntry {
            sequence: 0,
            sender_sequence: 10,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        session_history.add(entry.clone());

        assert!(session_history.latest == Some(0));
        assert!(session_history.history[0] == Some(entry));
        assert!(session_history.history[1].is_none());
    }

    #[test]
    fn simple_history_test_no_leftover_space() {
        let mut session_history = SessionHistory::new(2);

        let entry = SessionHistoryEntry {
            sequence: 0,
            sender_sequence: 10,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry2 = SessionHistoryEntry {
            sequence: 1,
            sender_sequence: 11,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };

        session_history.add(entry.clone());
        session_history.add(entry2.clone());

        assert!(session_history.latest == Some(1));
        assert!(session_history.history[0] == Some(entry));
        assert!(session_history.history[1] == Some(entry2));
    }

    #[test]
    fn simple_history_test_wraparound() {
        let mut session_history = SessionHistory::new(2);

        let entry = SessionHistoryEntry {
            sequence: 0,
            sender_sequence: 10,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry2 = SessionHistoryEntry {
            sequence: 1,
            sender_sequence: 11,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry3 = SessionHistoryEntry {
            sequence: 2,
            sender_sequence: 12,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };

        session_history.add(entry.clone());
        session_history.add(entry2.clone());
        session_history.add(entry3.clone());

        assert!(session_history.latest == Some(0));
        assert!(session_history.history[0] == Some(entry3));
        assert!(session_history.history[1] == Some(entry2));
    }

    #[test]
    fn simple_history_test_serialize() {
        let mut session_history = SessionHistory::new(2);

        let entry = SessionHistoryEntry {
            sequence: 0xab,
            sender_sequence: 10,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry2 = SessionHistoryEntry {
            sequence: 0xcd,
            sender_sequence: 11,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };

        session_history.add(entry.clone());
        session_history.add(entry2.clone());

        let result: Vec<_> = session_history.into();

        assert!(result[3] == 0xcd);
        assert!(result[35] == 0xab);
    }

    #[test]
    fn simple_history_test_wraparound_serialize() {
        let mut session_history = SessionHistory::new(2);

        let entry = SessionHistoryEntry {
            sequence: 0xab,
            sender_sequence: 10,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry2 = SessionHistoryEntry {
            sequence: 0xcd,
            sender_sequence: 11,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };
        let entry3 = SessionHistoryEntry {
            sequence: 0xef,
            sender_sequence: 12,
            received_time: ntp::NtpTime::now(),
            sender_time: ntp::NtpTime::now(),
            sent_time: ntp::NtpTime::now(),
        };

        session_history.add(entry.clone());
        session_history.add(entry2.clone());
        session_history.add(entry3.clone());

        let result: Vec<_> = session_history.into();

        assert!(result[3] == 0xef);
        assert!(result[35] == 0xcd);
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct SessionData {
    pub sequence: u32,
    pub last: std::time::SystemTime,
    pub key: Option<Vec<u8>>,
    pub history: SessionHistory,
}

impl SessionData {
    pub fn new(history_length: usize) -> SessionData {
        Self {
            sequence: 0u32,
            last: std::time::SystemTime::now(),
            key: None,
            history: SessionHistory::new(history_length),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Session {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub ssid: Ssid,
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let srcs = self.src.to_string();
        let dsts = self.dst.to_string();
        let mut struct_serializer = serializer.serialize_struct("Session", 4)?;
        struct_serializer.serialize_field("src", &srcs)?;
        struct_serializer.serialize_field("dst", &dsts)?;
        struct_serializer.serialize_field("ssid", &self.ssid)?;
        struct_serializer.end()
    }
}

impl Session {
    pub fn new(src: SocketAddr, dst: SocketAddr, ssid: Ssid) -> Self {
        Self { src, dst, ssid }
    }
}

#[derive(Debug, Clone)]
pub struct Sessions {
    pub sessions: Arc<Mutex<HashMap<Session, SessionData>>>,
}

impl Serialize for Sessions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct EmbeddedSession {
            id: Session,
            data: SessionData,
        }

        let sessions = self.sessions.lock().unwrap();

        let embedded_sessions: Vec<_> = sessions
            .iter()
            .map(|v| EmbeddedSession {
                id: v.0.clone(),
                data: v.1.clone(),
            })
            .collect();
        serde::Serialize::serialize(&embedded_sessions, serializer)
    }
}

#[derive(Clone, Debug)]
pub enum SessionError {
    SessionExists,
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::<HashMap<Session, SessionData>>::new(HashMap::<
                Session,
                SessionData,
            >::new(
            ))),
        }
    }

    pub fn maybe_new(&self, new: Session, new_sd: SessionData) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.keys().any(|e| *e == new) {
            return Err(SessionError::SessionExists);
        }

        sessions.insert(new, new_sd);
        Ok(())
    }
}

#[derive(Clone)]
pub struct ServerSocket {
    pub socket: Arc<Mutex<UdpSocket>>,
    pub socket_addr: net::SocketAddr,
}

impl ServerSocket {
    pub fn new(socket: UdpSocket, addr: net::SocketAddr) -> Self {
        Self {
            socket: Arc::new(Mutex::new(socket)),
            socket_addr: addr,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerCancellation {
    is_cancelled: Arc<Mutex<bool>>,
}

impl ServerCancellation {
    pub fn new() -> Self {
        Self {
            is_cancelled: Arc::new(Mutex::new(false)),
        }
    }

    pub fn cancel(&mut self) {
        let mut is_cancelled = self.is_cancelled.lock().unwrap();
        *is_cancelled = true;
    }

    pub fn is_cancelled(&self) -> bool {
        let is_cancelled = self.is_cancelled.lock().unwrap();
        *is_cancelled
    }
}
