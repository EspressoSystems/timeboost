use std::fmt::Display;

use crate::types::certificate::{NoVoteCertificate, TimeoutCertificate};
use crate::types::vertex::Vertex;
use hotshot_task::task::TaskEvent;
use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishEvent {
    Shutdown,
    DummySend(u64),
    DummyRecv(u64),
    VertexSend(Vertex),
    VertexRecv(Vertex),
    TimeoutSend(TimeoutCertificate),
    TimeoutRecv(TimeoutCertificate),
    NoVoteSend(NoVoteCertificate),
    NoVoteRecv(NoVoteCertificate),
}

impl TaskEvent for SailfishEvent {
    fn shutdown_event() -> Self {
        SailfishEvent::Shutdown
    }
}

impl Display for SailfishEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishEvent::VertexSend(v) => write!(f, "Vertex({})", v.round),
            SailfishEvent::TimeoutSend(timeout) => write!(f, "Timeout({})", timeout.round_number()),
            SailfishEvent::NoVoteSend(no_vote) => write!(f, "NoVote({})", no_vote.round_number()),
            SailfishEvent::VertexRecv(v) => write!(f, "VertexRecv({})", v.round),
            SailfishEvent::TimeoutRecv(timeout) => {
                write!(f, "TimeoutRecv({})", timeout.round_number())
            }
            SailfishEvent::NoVoteRecv(no_vote) => {
                write!(f, "NoVoteRecv({})", no_vote.round_number())
            }
            SailfishEvent::Shutdown => write!(f, "Shutdown"),
            SailfishEvent::DummySend(n) => write!(f, "DummySend({})", n),
            SailfishEvent::DummyRecv(n) => write!(f, "DummyRecv({})", n),
        }
    }
}
