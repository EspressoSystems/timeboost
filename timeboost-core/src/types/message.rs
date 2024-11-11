use core::fmt;
use std::ops::Deref;

use crate::types::vertex::Vertex;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use super::{
    certificate::Certificate,
    envelope::{Envelope, Unchecked, Validated},
    PublicKey,
};
use crate::types::block::Block;
use crate::types::committee::StaticCommittee;
use crate::types::round_number::RoundNumber;
use crate::types::signed::Signed;
use crate::types::Keypair;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Message {
    /// A vertex proposal from a node.
    Vertex(Envelope<Vertex, Unchecked>),

    /// A timeout message from a node.
    Timeout(Envelope<TimeoutMessage, Unchecked>),

    /// A no-vote to a round leader from a node.
    NoVote(Envelope<NoVoteMessage, Unchecked>),

    /// A timeout certificate from a node.
    TimeoutCert(Certificate<Timeout>),
}

impl Message {
    pub fn round(&self) -> RoundNumber {
        match self {
            Message::Vertex(v) => *v.data().round().data(),
            Message::Timeout(t) => **t.data().round().data(),
            Message::NoVote(nv) => **nv.data().round().data(),
            Message::TimeoutCert(c) => **c.data(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action {
    /// Reset the timer to the given round.
    ResetTimer(RoundNumber),

    /// Deliver a block to the application layer.
    Deliver(Block, RoundNumber, PublicKey),

    /// Send a vertex proposal to all nodes.
    SendProposal(Envelope<Vertex, Validated>),

    /// Send a timeout message to all nodes.
    SendTimeout(Envelope<TimeoutMessage, Validated>),

    /// Send a no-vote message to the given node.
    SendNoVote(PublicKey, Envelope<NoVoteMessage, Validated>),

    /// Send a timeout certificate to all nodes.
    SendTimeoutCert(Certificate<Timeout>),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::ResetTimer(round) => write!(f, "ResetTimer({})", round),
            Action::Deliver(_, round, _) => write!(f, "Deliver({})", round),
            Action::SendProposal(envelope) => {
                write!(f, "SendProposal({})", envelope.data().round().data())
            }
            Action::SendTimeout(envelope) => {
                write!(f, "SendTimeout({})", envelope.data().round().data())
            }
            Action::SendNoVote(ver_key, envelope) => {
                write!(
                    f,
                    "SendNoVote({}, {})",
                    ver_key,
                    envelope.data().round().data()
                )
            }
            Action::SendTimeoutCert(certificate) => {
                write!(f, "SendTimeoutCert({})", certificate.data())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Timeout(RoundNumber);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVote(RoundNumber);

impl Deref for Timeout {
    type Target = RoundNumber;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for NoVote {
    type Target = RoundNumber;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for NoVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TimeoutMessage {
    round: Signed<Timeout>,
    evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVoteMessage {
    round: Signed<NoVote>,
    evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum Evidence {
    Regular(Certificate<RoundNumber>),
    Timeout(Certificate<Timeout>),
}

impl Evidence {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Regular(x) => *x.data(),
            Self::Timeout(x) => x.data().0,
        }
    }

    pub fn is_valid_quorum(&self, c: &StaticCommittee) -> bool {
        match self {
            Self::Regular(x) => x.is_valid_quorum(c),
            Self::Timeout(x) => x.is_valid_quorum(c),
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }
}

impl From<Certificate<RoundNumber>> for Evidence {
    fn from(value: Certificate<RoundNumber>) -> Self {
        Self::Regular(value)
    }
}

impl From<Certificate<Timeout>> for Evidence {
    fn from(value: Certificate<Timeout>) -> Self {
        Self::Timeout(value)
    }
}

impl TimeoutMessage {
    pub fn new<N>(r: N, e: Evidence, k: &Keypair) -> Self
    where
        N: Into<RoundNumber>,
    {
        let r = r.into();
        debug_assert_eq!(e.round() + 1, r);
        Self {
            round: Signed::new(Timeout(r), k),
            evidence: e,
        }
    }

    pub fn round(&self) -> &Signed<Timeout> {
        &self.round
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn into_parts(self) -> (Signed<Timeout>, Evidence) {
        (self.round, self.evidence)
    }
}

impl NoVoteMessage {
    pub fn new<N>(r: N, e: Certificate<Timeout>, k: &Keypair) -> Self
    where
        N: Into<RoundNumber>,
    {
        let r = r.into();
        debug_assert_eq!(**e.data() + 1, r);
        Self {
            round: Signed::new(NoVote(r), k),
            evidence: Evidence::Timeout(e),
        }
    }

    pub fn round(&self) -> &Signed<NoVote> {
        &self.round
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn into_parts(self) -> (Signed<NoVote>, Evidence) {
        (self.round, self.evidence)
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
            Self::Vertex(e) => write!(f, "Vertex({})", e.data().round().data()),
            Self::Timeout(e) => write!(f, "Timeout({})", e.data().round().data().0),
            Self::NoVote(e) => write!(f, "NoVote({})", e.data().round().data().0),
            Self::TimeoutCert(c) => write!(f, "TimeoutCert({})", c.data().0),
        }
    }
}

impl Committable for TimeoutMessage {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("TimeoutMessage")
            .field("round", self.round.commit())
            .field("evidence", self.evidence.commit())
            .finalize()
    }
}

impl Committable for NoVoteMessage {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("NoVoteMessage")
            .field("round", self.round.commit())
            .field("evidence", self.evidence.commit())
            .finalize()
    }
}

impl Committable for Timeout {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Timeout")
            .field("round", self.0.commit())
            .finalize()
    }
}

impl Committable for NoVote {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("NoVote")
            .field("round", self.0.commit())
            .finalize()
    }
}

impl Committable for Evidence {
    fn commit(&self) -> Commitment<Self> {
        match self {
            Self::Regular(c) => RawCommitmentBuilder::new("Evidence::Regular")
                .field("cert", c.commit())
                .finalize(),
            Self::Timeout(c) => RawCommitmentBuilder::new("Evidence::Timeout")
                .field("cert", c.commit())
                .finalize(),
        }
    }
}
