use core::fmt;

use crate::types::vertex::Vertex;
use committable::{Commitment, Committable};
use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};

use super::{
    block::Block,
    certificate::Certificate,
    envelope::{Envelope, Unchecked, Validated},
    PublicKey,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Message {
    /// A vertex proposal from a node.
    Vertex(Envelope<Vertex, Unchecked>),
    /// A timeout message from a node.
    Timeout(Envelope<Timeout, Unchecked>),
    /// A no-vote to a round leader from a node.
    NoVote(Envelope<NoVote, Unchecked>),
    /// A timeout certificate from a node.
    TimeoutCert(Certificate<Timeout>),
}

#[derive(Debug, Clone)]
pub enum Action {
    ResetTimer(ViewNumber),
    Deliver(Block, ViewNumber, PublicKey),
    SendProposal(Envelope<Vertex, Validated>),
    SendTimeout(Envelope<Timeout, Validated>),
    SendNoVote(PublicKey, Envelope<NoVote, Validated>),
    SendTimeoutCert(Certificate<Timeout>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Timeout {
    pub round: ViewNumber,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVote {
    round: ViewNumber,
}

impl Timeout {
    pub fn new(r: ViewNumber) -> Self {
        Self { round: r }
    }

    pub fn round(&self) -> ViewNumber {
        self.round
    }
}

impl NoVote {
    pub fn new(r: ViewNumber) -> Self {
        Self { round: r }
    }

    pub fn round(&self) -> ViewNumber {
        self.round
    }
}

impl Message {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        bincode::serialize_into(buf, self).expect("serializing a `Message` never fails")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serializing a `Message` never fails")
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vertex(e) => write!(f, "vertex proposal, id := {}", e.data().id()),
            Self::Timeout(e) => write!(f, "timeout, round := {}", e.data().round),
            Self::NoVote(e) => write!(f, "no-vote, round := {}", e.data().round),
            Self::TimeoutCert(c) => write!(f, "timeout cert, round := {}", c.data().round),
        }
    }
}

impl Committable for Timeout {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("Timeout")
            .field("round", self.round.commit())
            .finalize()
    }
}

impl Committable for NoVote {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("NoVote")
            .field("round", self.round.commit())
            .finalize()
    }
}
