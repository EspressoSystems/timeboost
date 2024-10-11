use std::fmt::Display;

use crate::types::certificate::{NoVoteCertificate, TimeoutCertificate};
use crate::types::vertex::Vertex;
use hotshot_task::task::TaskEvent;

#[derive(Eq, PartialEq, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishMessage {
    Shutdown,
    Vertex(Vertex),
    Timeout(TimeoutCertificate),
    NoVote(NoVoteCertificate),
}

impl TaskEvent for SailfishMessage {
    fn shutdown_event() -> Self {
        SailfishMessage::Shutdown
    }
}

impl Display for SailfishMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishMessage::Vertex(v) => write!(f, "Vertex({})", v.round),
            SailfishMessage::Timeout(timeout) => write!(f, "Timeout({})", timeout.round_number()),
            SailfishMessage::NoVote(no_vote) => write!(f, "NoVote({})", no_vote.round_number()),
            SailfishMessage::Shutdown => write!(f, "Shutdown"),
        }
    }
}
