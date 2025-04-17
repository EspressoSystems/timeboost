use core::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{
    Certificate, Committee, Envelope, Keypair, PublicKey, Signed, Unchecked, Validated,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{RoundNumber, Vertex};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Message<T: Committable, Status = Validated> {
    /// A vertex proposal from a node.
    Vertex(Envelope<Vertex<T>, Status>),

    /// A timeout message from a node.
    Timeout(Envelope<TimeoutMessage, Status>),

    /// A no-vote to a round leader from a node.
    NoVote(Envelope<NoVoteMessage, Status>),

    /// A timeout certificate from a node.
    TimeoutCert(Certificate<Timeout>),
}

impl<T: Committable, S> Message<T, S> {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Vertex(v) => *v.data().round().data(),
            Self::Timeout(t) => t.data().timeout().data().round(),
            Self::NoVote(nv) => nv.data().no_vote().data().round(),
            Self::TimeoutCert(c) => c.data().round(),
        }
    }

    pub fn signing_key(&self) -> Option<&PublicKey> {
        match self {
            Self::Vertex(e) => Some(e.signing_key()),
            Self::Timeout(e) => Some(e.signing_key()),
            Self::NoVote(e) => Some(e.signing_key()),
            Self::TimeoutCert(_) => None,
        }
    }

    pub fn is_vertex(&self) -> bool {
        matches!(self, Self::Vertex(_))
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    pub fn is_no_vote(&self) -> bool {
        matches!(self, Self::NoVote(_))
    }

    pub fn is_timeout_cert(&self) -> bool {
        matches!(self, Self::TimeoutCert(_))
    }
}

impl<T: Committable> Message<T, Unchecked> {
    pub fn validated(self, c: &Committee) -> Option<Message<T, Validated>> {
        match self {
            Self::Vertex(e) => {
                // Validate the envelope's signature:
                let Some(e) = e.validated(c) else {
                    warn!("invalid envelope signature");
                    return None;
                };

                let signer = e.signing_key();

                // The signer should be the producer of the vertex:
                if signer != e.data().source() {
                    warn!(%signer, source = %e.data().source(), "envelope signer != vertex source");
                    return None;
                }

                // Validate the round signature:
                if !e.data().round().is_valid(c) {
                    warn!(%signer, "invalid round signature");
                    return None;
                }

                // The signer of the envelope should also be the same as the one who signed
                // the round number certificate:
                if signer != e.data().round().signing_key() {
                    warn!(
                        %signer,
                        round = %e.data().round().signing_key(),
                        "envelope signer != vertex round signer"
                    );
                    return None;
                }

                // Validate the previous round evidence:
                if !e.data().evidence().is_valid(*e.data().round().data(), c) {
                    warn!(%signer, "invalid evidence in vertex");
                    return None;
                }

                // The following check does not apply to the genesis round:
                if *e.data().round().data() != RoundNumber::genesis() {
                    // The number of vertex edges must be >= to the committee quorum:
                    if e.data().num_edges() < c.quorum_size().get() {
                        warn!(%signer, "vertex has not enough edges");
                        return None;
                    }
                }

                // No-vote certificate validation:
                if let Some(cert) = e.data().no_vote_cert() {
                    if !cert.is_valid_par(c) {
                        warn!(%signer, "invalid no-vote certificate in vertex");
                        return None;
                    }
                    // The no-vote certificate should apply to the immediate predecessor
                    // of the current vertex round:
                    if cert.data().round() + 1 != *e.data().round().data() {
                        warn!(%signer, "no-vote certificate in vertex applies to invalid round");
                        return None;
                    }
                }

                Some(Message::Vertex(e))
            }
            Self::Timeout(e) => {
                // Validate the envelope's signature:
                let Some(e) = e.validated(c) else {
                    warn!("invalid envelope signature");
                    return None;
                };

                let signer = e.signing_key();

                // The signer should be the producer of the timeout message:
                if signer != e.data().timeout().signing_key() {
                    warn!(
                        %signer,
                        timeout = %e.data().timeout().signing_key(),
                        "envelope signer != timeout signer"
                    );
                    return None;
                }

                // Validate the timeout signature:
                if !e.data().timeout().is_valid(c) {
                    warn!(%signer, "invalid timeout signature");
                    return None;
                }

                // Validate the signature of the previous round evidence:
                if !e
                    .data()
                    .evidence()
                    .is_valid(e.data().timeout().data().round(), c)
                {
                    warn!(%signer, "invalid timeout evidence");
                    return None;
                }

                Some(Message::Timeout(e))
            }
            Self::NoVote(e) => {
                // Validate the envelope's signature:
                let Some(e) = e.validated(c) else {
                    warn!("invalid envelope signature");
                    return None;
                };

                let signer = e.signing_key();

                // The signer should be the producer of the no-vote message:
                if signer != e.data().no_vote().signing_key() {
                    warn!(
                        %signer,
                        no_vote = %e.data().no_vote().signing_key(),
                        "envelope signer != no-vote signer"
                    );
                    return None;
                }

                // Validate the no-vote signature:
                if !e.data().no_vote().is_valid(c) {
                    warn!(%signer, "invalid no-vote signature");
                    return None;
                }

                // Validate the timeout certificate signatures:
                if !e.data().certificate().is_valid_par(c) {
                    warn!(%signer, "invalid no-vote certificate");
                    return None;
                }

                // The no-vote should apply to the same round as the timeout certificate:
                if e.data().no_vote().data().round() != e.data().certificate().data().round() {
                    warn!(%signer, "no-vote certificate applies to invalid round");
                    return None;
                }

                Some(Message::NoVote(e))
            }
            Self::TimeoutCert(crt) => {
                // Validate the timeout certificate signatures:
                if !crt.is_valid_par(c) {
                    warn!("invalid timeout certiticate");
                    return None;
                }

                Some(Message::TimeoutCert(crt))
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Payload<T: Committable> {
    round: RoundNumber,
    source: PublicKey,
    data: T,
}

impl<T: Committable> Payload<T> {
    pub fn new(round: RoundNumber, source: PublicKey, data: T) -> Self {
        Self {
            round,
            source,
            data,
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn source(&self) -> PublicKey {
        self.source
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_data(self) -> T {
        self.data
    }

    pub fn into_parts(self) -> (RoundNumber, PublicKey, T) {
        (self.round, self.source, self.data)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action<T: Committable> {
    /// Reset the timer to the given round.
    ResetTimer(RoundNumber),

    /// Deliver payload data to the application layer.
    Deliver(Payload<T>),

    /// Send a vertex proposal to all nodes.
    SendProposal(Envelope<Vertex<T>, Validated>),

    /// Send a timeout message to all nodes.
    SendTimeout(Envelope<TimeoutMessage, Validated>),

    /// Send a no-vote message to the given node.
    SendNoVote(PublicKey, Envelope<NoVoteMessage, Validated>),

    /// Send a timeout certificate to all nodes.
    SendTimeoutCert(Certificate<Timeout>),

    /// Signal that it is safe to garbage collect up to the given round number.
    Gc(RoundNumber),
}

impl<T: Committable> Action<T> {
    pub fn is_deliver(&self) -> bool {
        matches!(self, Self::Deliver(_))
    }
}

impl<T: Committable> fmt::Display for Action<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::ResetTimer(round) => write!(f, "ResetTimer({})", round),
            Action::Deliver(data) => write!(f, "Deliver({},{})", data.round, data.source),
            Action::SendProposal(envelope) => {
                write!(f, "SendProposal({})", envelope.data().round().data())
            }
            Action::SendTimeout(envelope) => {
                write!(
                    f,
                    "SendTimeout({})",
                    envelope.data().timeout().data().round()
                )
            }
            Action::SendNoVote(ver_key, envelope) => {
                write!(
                    f,
                    "SendNoVote({}, {})",
                    ver_key,
                    envelope.data().no_vote().data().round()
                )
            }
            Action::SendTimeoutCert(certificate) => {
                write!(f, "SendTimeoutCert({})", certificate.data().round())
            }
            Action::Gc(r) => {
                write!(f, "Gc({r})")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct Timeout {
    round: RoundNumber,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Evidence {
    Genesis,
    Regular(Certificate<RoundNumber>),
    Timeout(Certificate<Timeout>),
}

impl Evidence {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Genesis => RoundNumber::genesis(),
            Self::Regular(x) => *x.data(),
            Self::Timeout(x) => x.data().round,
        }
    }

    pub fn is_valid(&self, r: RoundNumber, c: &Committee) -> bool {
        match self {
            Self::Genesis => r.is_genesis(),
            Self::Regular(x) => self.round() + 1 == r && x.is_valid_par(c),
            Self::Timeout(x) => self.round() + 1 == r && x.is_valid_par(c),
        }
    }

    pub fn is_genesis(&self) -> bool {
        matches!(self, Self::Genesis)
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TimeoutMessage {
    timeout: Signed<Timeout>,
    evidence: Evidence,
}

impl TimeoutMessage {
    pub fn new(e: Evidence, k: &Keypair, deterministic: bool) -> Self {
        let t = Timeout::new(if e.is_genesis() {
            e.round()
        } else {
            e.round() + 1
        });
        Self {
            timeout: Signed::new(t, k, deterministic),
            evidence: e,
        }
    }

    pub fn timeout(&self) -> &Signed<Timeout> {
        &self.timeout
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn into_parts(self) -> (Signed<Timeout>, Evidence) {
        (self.timeout, self.evidence)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVoteMessage {
    no_vote: Signed<NoVote>,
    evidence: Certificate<Timeout>,
}

impl NoVoteMessage {
    pub fn new(e: Certificate<Timeout>, k: &Keypair, deterministic: bool) -> Self {
        Self {
            no_vote: Signed::new(NoVote::new(e.data().round), k, deterministic),
            evidence: e,
        }
    }

    pub fn no_vote(&self) -> &Signed<NoVote> {
        &self.no_vote
    }

    pub fn certificate(&self) -> &Certificate<Timeout> {
        &self.evidence
    }

    pub fn into_parts(self) -> (Signed<NoVote>, Certificate<Timeout>) {
        (self.no_vote, self.evidence)
    }
}

impl<'a, T: Committable + Deserialize<'a>> Message<T, Unchecked> {
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        bincode::serde::borrow_decode_from_slice(bytes, bincode::config::standard())
            .ok()
            .map(|(msg, _)| msg)
    }
}

impl<T: Committable + Serialize, S: Serialize> Message<T, S> {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        bincode::serde::encode_into_std_write(self, buf, bincode::config::standard())
            .expect("serializing a `Message` never fails");
    }

    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("serializing a `Message` never fails")
    }
}

impl<T: Committable, S> fmt::Display for Message<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vertex(e) => {
                let r = e.data().round().data();
                let s = e.data().source();
                write!(f, "Vertex({r},{s})")
            }
            Self::Timeout(e) => {
                let r = e.data().timeout().data().round();
                let s = e.signing_key();
                write!(f, "Timeout({r},{s})")
            }
            Self::NoVote(e) => {
                let r = e.data().no_vote().data().round();
                let s = e.signing_key();
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

impl Committable for TimeoutMessage {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("TimeoutMessage")
            .field("timeout", self.timeout.commit())
            .field("evidence", self.evidence.commit())
            .finalize()
    }
}

impl Committable for NoVoteMessage {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("NoVoteMessage")
            .field("no_vote", self.no_vote.commit())
            .field("evidence", self.evidence.commit())
            .finalize()
    }
}

impl Committable for Evidence {
    fn commit(&self) -> Commitment<Self> {
        match self {
            Self::Genesis => RawCommitmentBuilder::new("Evidence::Genesis").finalize(),
            Self::Regular(c) => RawCommitmentBuilder::new("Evidence::Regular")
                .field("cert", c.commit())
                .finalize(),
            Self::Timeout(c) => RawCommitmentBuilder::new("Evidence::Timeout")
                .field("cert", c.commit())
                .finalize(),
        }
    }
}

impl<T: Committable, S> Committable for Message<T, S> {
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

impl<T: Committable> Committable for Payload<T> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Payload")
            .field("round", self.round.commit())
            .fixed_size_field("source", &self.source.as_bytes())
            .field("data", self.data.commit())
            .finalize()
    }
}
