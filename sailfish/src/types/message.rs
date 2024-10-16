use std::fmt::Display;

use crate::types::{
    certificate::{NoVoteCertificate, TimeoutCertificate},
    vertex::Vertex,
};
use hotshot_types::vote::HasViewNumber;
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

impl Display for SailfishEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishEvent::VertexSend(v) => write!(f, "Vertex({})", v.round),
            SailfishEvent::TimeoutSend(timeout) => {
                write!(f, "Timeout({})", timeout.view_number())
            }
            SailfishEvent::NoVoteSend(no_vote) => write!(f, "NoVote({})", no_vote.view_number()),
            SailfishEvent::VertexRecv(v) => write!(f, "VertexRecv({})", v.round),
            SailfishEvent::TimeoutRecv(timeout) => {
                write!(f, "TimeoutRecv({})", timeout.view_number())
            }
            SailfishEvent::NoVoteRecv(no_vote) => {
                write!(f, "NoVoteRecv({})", no_vote.view_number())
            }
            SailfishEvent::Shutdown => write!(f, "Shutdown"),
            SailfishEvent::DummySend(n) => write!(f, "DummySend({})", n),
            SailfishEvent::DummyRecv(n) => write!(f, "DummyRecv({})", n),
        }
    }
}
