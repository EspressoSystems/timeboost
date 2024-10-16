use std::fmt::Display;

use crate::types::vertex::Vertex;
use hotshot_types::{data::ViewNumber, vote::HasViewNumber};
use serde::{Deserialize, Serialize};

use super::vote::{NoVoteVote, TimeoutVote, VertexVote};

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishEvent {
    Shutdown,
    DummySend(u64),
    DummyRecv(u64),
    VertexSend(Vertex),
    VertexRecv(Vertex),
    TimeoutSend(ViewNumber),
    TimeoutRecv(ViewNumber),
    NoVoteSend(ViewNumber),
    NoVoteRecv(ViewNumber),
    TimeoutVoteSend(TimeoutVote),
    TimeoutVoteRecv(TimeoutVote),
    NoVoteVoteSend(NoVoteVote),
    NoVoteVoteRecv(NoVoteVote),
    VertexVoteSend(VertexVote),
    VertexVoteRecv(VertexVote),
}

impl Display for SailfishEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishEvent::VertexSend(v) => write!(f, "Vertex({})", v.round),
            SailfishEvent::TimeoutSend(view_number) => {
                write!(f, "Timeout({})", view_number)
            }
            SailfishEvent::NoVoteSend(view_number) => write!(f, "NoVote({})", view_number),
            SailfishEvent::VertexRecv(v) => write!(f, "VertexRecv({})", v.round),
            SailfishEvent::TimeoutRecv(view_number) => write!(f, "TimeoutRecv({})", view_number),
            SailfishEvent::NoVoteRecv(view_number) => write!(f, "NoVoteRecv({})", view_number),
            SailfishEvent::TimeoutVoteSend(vote) => {
                write!(f, "TimeoutVote({})", vote.view_number())
            }
            SailfishEvent::TimeoutVoteRecv(vote) => {
                write!(f, "TimeoutVoteRecv({})", vote.view_number())
            }
            SailfishEvent::NoVoteVoteSend(vote) => {
                write!(f, "NoVoteVote({})", vote.view_number())
            }
            SailfishEvent::NoVoteVoteRecv(vote) => {
                write!(f, "NoVoteVoteRecv({})", vote.view_number())
            }
            SailfishEvent::VertexVoteSend(vote) => {
                write!(f, "VertexVoteSend({})", vote.view_number())
            }
            SailfishEvent::VertexVoteRecv(vote) => {
                write!(f, "VertexVoteRecv({})", vote.view_number())
            }
            SailfishEvent::Shutdown => write!(f, "Shutdown"),
            SailfishEvent::DummySend(n) => write!(f, "DummySend({})", n),
            SailfishEvent::DummyRecv(n) => write!(f, "DummyRecv({})", n),
        }
    }
}
