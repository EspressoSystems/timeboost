use std::fmt::Display;

use crate::types::vertex::Vertex;
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::{data::ViewNumber, vote::HasViewNumber};
use serde::{Deserialize, Serialize};

use super::{
    certificate::VertexCertificate,
    vote::{NoVoteVote, TimeoutVote, VertexVote},
};

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishEvent {
    /// Signal a shutdown to the node.
    Shutdown,

    /// Send a vertex to the network.
    VertexSend(
        Vertex,
        <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ),

    /// Receive a vertex from the network.
    VertexRecv(
        Vertex,
        <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ),

    /// Send a timeout to the network.
    TimeoutSend(ViewNumber),

    /// Receive a timeout from the network.
    TimeoutRecv(ViewNumber),

    /// Send a no-vote to the network.
    NoVoteSend(ViewNumber),

    /// Receive a no-vote from the network.
    NoVoteRecv(ViewNumber),

    /// Send a timeout vote to the network.
    TimeoutVoteSend(TimeoutVote),

    /// Receive a timeout vote from the network.
    TimeoutVoteRecv(TimeoutVote),

    /// Send a no-vote vote to the network.
    NoVoteVoteSend(NoVoteVote),

    /// Receive a no-vote vote from the network.
    NoVoteVoteRecv(NoVoteVote),

    /// Send a vertex vote to the network.
    VertexVoteSend(VertexVote),

    /// Receive a vertex vote from the network.
    VertexVoteRecv(VertexVote),

    /// Commit a vertex, signed by the leader of the round being committed.
    VertexCommitted(
        ViewNumber,
        <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ),

    /// Change to a new round.
    RoundChange(ViewNumber),

    /// The vertex certificate has been generated.
    VertexCertificateSend(VertexCertificate),

    /// The vertex certificate has been received.
    VertexCertificateRecv(VertexCertificate),
}

impl Display for SailfishEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishEvent::VertexSend(v, _) => {
                write!(f, "VertexSend({})", v.round)
            }
            SailfishEvent::TimeoutSend(round) => {
                write!(f, "TimeoutSend({})", round)
            }
            SailfishEvent::NoVoteSend(round) => write!(f, "NoVoteSend({})", round),
            SailfishEvent::VertexRecv(v, _) => {
                write!(f, "VertexRecv({})", v.round)
            }
            SailfishEvent::TimeoutRecv(round) => write!(f, "TimeoutRecv({})", round),
            SailfishEvent::NoVoteRecv(round) => write!(f, "NoVoteRecv({})", round),
            SailfishEvent::TimeoutVoteSend(vote) => {
                write!(f, "TimeoutVoteSend({})", vote.view_number())
            }
            SailfishEvent::TimeoutVoteRecv(vote) => {
                write!(f, "TimeoutVoteRecv({})", vote.view_number())
            }
            SailfishEvent::NoVoteVoteSend(vote) => {
                write!(f, "NoVoteVoteSend({})", vote.view_number())
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
            SailfishEvent::VertexCommitted(round, _) => {
                write!(f, "VertexCommitted({})", round)
            }
            SailfishEvent::RoundChange(round) => {
                write!(f, "RoundChange({})", round)
            }
            SailfishEvent::Shutdown => write!(f, "Shutdown"),
            SailfishEvent::VertexCertificateSend(cert) => {
                write!(f, "VertexCertificateSend({})", cert.view_number())
            }
            SailfishEvent::VertexCertificateRecv(cert) => {
                write!(f, "VertexCertificateRecv({})", cert.view_number())
            }
        }
    }
}

impl SailfishEvent {
    pub fn transform_send_to_recv(self) -> Self {
        match self {
            Self::VertexSend(vertex, signature) => Self::VertexRecv(vertex, signature),
            Self::TimeoutSend(view_number) => Self::TimeoutRecv(view_number),
            Self::NoVoteSend(view_number) => Self::NoVoteRecv(view_number),
            Self::TimeoutVoteSend(vote) => Self::TimeoutVoteRecv(vote),
            Self::NoVoteVoteSend(vote) => Self::NoVoteVoteRecv(vote),
            Self::VertexVoteSend(vote) => Self::VertexVoteRecv(vote),
            Self::VertexCertificateSend(cert) => Self::VertexCertificateRecv(cert),
            _ => self,
        }
    }
}
