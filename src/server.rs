use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use nix::sys::socket::SockaddrIn;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Session {
    pub src: SockaddrIn,
    pub dst: SockaddrIn,
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SessionData {
    pub sequence: u32,
}

impl SessionData {
    pub fn new() -> SessionData {
        Self { sequence: 0u32 }
    }
}

impl Session {
    pub fn new(src: SockaddrIn, dst: SockaddrIn) -> Self {
        Self {
            src,
            dst,
        }
    }
}

#[derive(Clone)]
pub struct Sessions {
    pub sessions: Arc<Mutex<HashMap<Session, SessionData>>>,
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
}
