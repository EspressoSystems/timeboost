use std::fmt::Display;

use crate::types::certificate::{NoVoteCertificate, TimeoutCertificate};
use crate::types::vertex::Vertex;
use hotshot_task::task::TaskEvent;

#[derive(Eq, PartialEq, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishEvent {
    Shutdown,
    Vertex(Vertex),
    Timeout(TimeoutCertificate),
    NoVote(NoVoteCertificate),
}

impl TaskEvent for SailfishEvent {
    fn shutdown_event() -> Self {
        SailfishEvent::Shutdown
    }
}

impl Display for SailfishEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishEvent::Vertex(v) => write!(f, "Vertex({})", v.round),
            SailfishEvent::Timeout(timeout) => write!(f, "Timeout({})", timeout.round_number()),
            SailfishEvent::NoVote(no_vote) => write!(f, "NoVote({})", no_vote.round_number()),
            SailfishEvent::Shutdown => write!(f, "Shutdown"),
        }
    }
}
