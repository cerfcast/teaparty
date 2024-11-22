use crate::{periodicity::Periodicity, server::Sessions};


#[derive(Debug, Clone)]
pub struct Monitor {
    pub periodic: Periodicity,
    pub sessions: Sessions
}