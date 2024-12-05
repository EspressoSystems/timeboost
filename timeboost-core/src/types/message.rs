use core::fmt;

use crate::types::vertex::Vertex;
use crate::types::Label;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use timeboost_utils::types::round_number::RoundNumber;

use super::{
    certificate::Certificate,
    envelope::{Envelope, Unchecked, Validated},
    PublicKey,
};
use crate::types::{block::sailfish::SailfishBlock, committee::StaticCommittee};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Message<Status = Validated> {
    /// A vertex proposal from a node.
    Vertex(Envelope<Vertex, Status>),

    /// A timeout message from a node.
    Timeout(Envelope<Timeout, Status>),

    /// A no-vote to a round leader from a node.
    NoVote(Envelope<NoVote, Status>),

    /// A timeout certificate from a node.
    TimeoutCert(Certificate<Timeout>),
}

impl<S> Message<S> {
    pub fn round(&self) -> RoundNumber {
        match self {
            Message::Vertex(v) => v.data().round(),
            Message::Timeout(t) => t.data().round(),
            Message::NoVote(nv) => nv.data().round(),
            Message::TimeoutCert(c) => c.data().round(),
        }
    }
}

impl Message<Unchecked> {
    pub fn validated(self, c: &StaticCommittee) -> Option<Message<Validated>> {
        match self {
            Self::Vertex(e) => e.validated(c).map(Message::Vertex),
            Self::Timeout(e) => e.validated(c).map(Message::Timeout),
            Self::NoVote(e) => e.validated(c).map(Message::NoVote),
            Self::TimeoutCert(c) => Some(Message::TimeoutCert(c)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action {
    /// Reset the timer to the given round.
    ResetTimer(RoundNumber),

    /// Deliver a block to the application layer.
    Deliver(SailfishBlock, RoundNumber, PublicKey),

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
    round: RoundNumber,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVote {
    round: RoundNumber,
}

impl Timeout {
    pub fn new<N: Into<RoundNumber>>(r: N) -> Self {
        Self { round: r.into() }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }
}

impl NoVote {
    pub fn new<N: Into<RoundNumber>>(r: N) -> Self {
        Self { round: r.into() }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }
}

impl Message<Unchecked> {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

impl<S: Serialize> Message<S> {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        bincode::serialize_into(buf, self).expect("serializing a `Message` never fails")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serialize(self).expect("serializing a `Message` never fails")
    }
}

impl<S> fmt::Display for Message<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vertex(e) => {
                let r = e.data().round();
                let s = Label::new(e.data().source());
                write!(f, "Vertex({r},{s})")
            }
            Self::Timeout(e) => {
                let r = e.data().round();
                let s = Label::new(e.signing_key());
                write!(f, "Timeout({r},{s})")
            }
            Self::NoVote(e) => {
                let r = e.data().round();
                let s = Label::new(e.signing_key());
                write!(f, "NoVote({r},{s})")
            }
            Self::TimeoutCert(c) => {
                write!(f, "TimeoutCert({})", c.data().round)
            }
        }
    }
}

impl Committable for Timeout {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Timeout")
            .field("round", self.round.commit())
            .finalize()
    }
}

impl Committable for NoVote {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("NoVote")
            .field("round", self.round.commit())
            .finalize()
    }
}

impl<S> Committable for Message<S> {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Message");
        match self {
            Self::Vertex(e) => builder.field("vertex", e.commit()).finalize(),
            Self::Timeout(e) => builder.field("timeout", e.commit()).finalize(),
            Self::NoVote(e) => builder.field("novote", e.commit()).finalize(),
            Self::TimeoutCert(c) => builder.field("timeout-cert", c.commit()).finalize(),
        }
    }
}
