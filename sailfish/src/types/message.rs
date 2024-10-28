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

impl Message {
    pub fn round(&self) -> ViewNumber {
        match self {
            Message::Vertex(v) => v.data().round(),
            Message::Timeout(t) => t.data().round(),
            Message::NoVote(nv) => nv.data().round(),
            Message::TimeoutCert(c) => c.data().round(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action {
    /// Reset the timer to the given round.
    ResetTimer(ViewNumber),

    /// Deliver a block to the application layer.
    Deliver(Block, ViewNumber, PublicKey),

    /// Send a vertex proposal to all nodes.
    SendProposal(Envelope<Vertex, Validated>),

    /// Send a timeout message to all nodes.
    SendTimeout(Envelope<Timeout, Validated>),

    /// Send a no-vote message to the given node.
    SendNoVote(PublicKey, Envelope<NoVote, Validated>),

    /// Send a timeout certificate to all nodes.
    SendTimeoutCert(Certificate<Timeout>),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::ResetTimer(round) => write!(f, "ResetTimer({})", round),
            Action::Deliver(_, round, _) => write!(f, "Deliver({})", round),
            Action::SendProposal(envelope) => {
                write!(f, "SendProposal({})", envelope.data().round())
            }
            Action::SendTimeout(envelope) => write!(f, "SendTimeout({})", envelope.data().round()),
            Action::SendNoVote(ver_key, envelope) => {
                write!(f, "SendNoVote({}, {})", ver_key, envelope.data().round())
            }
            Action::SendTimeoutCert(certificate) => {
                write!(f, "SendTimeoutCert({})", certificate.data().round())
            }
        }
    }
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
            Self::Vertex(e) => write!(f, "Vertex({})", e.data().id().round()),
            Self::Timeout(e) => write!(f, "Timeout({})", e.data().round),
            Self::NoVote(e) => write!(f, "NoVote({})", e.data().round),
            Self::TimeoutCert(c) => write!(f, "TimeoutCert({})", c.data().round),
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
