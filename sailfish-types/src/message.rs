use core::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{
    Certificate, CommitteeId, Envelope, KeyId, Keypair, PublicKey, Signed, Unchecked, Validated,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{CommitteeVec, GENESIS_ROUND, Round, RoundNumber, Vertex};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Event<T: Committable, Status = Validated> {
    Message(Message<T, Status>),
    Info(Info),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Info {
    /// At least 2t + 1 vertex proposals with an edge to the leader of the
    /// given round number have been received.
    LeaderThresholdReached(RoundNumber),
}

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

    /// A handover message from a node.
    Handover(Envelope<HandoverMessage, Status>),

    /// A handover certificate from a node.
    HandoverCert(Certificate<Handover>),
}

impl<T: Committable, S> Message<T, S> {
    pub fn round(&self) -> Round {
        match self {
            Self::Vertex(v) => *v.data().round().data(),
            Self::Timeout(t) => t.data().timeout().data().round(),
            Self::NoVote(nv) => nv.data().no_vote().data().round(),
            Self::Handover(h) => h.data().handover().data().round(),
            Self::TimeoutCert(c) => c.data().round(),
            Self::HandoverCert(c) => c.data().round(),
        }
    }

    pub fn committee(&self) -> CommitteeId {
        match self {
            Self::Vertex(v) => v.data().round().data().committee(),
            Self::Timeout(t) => t.data().timeout().data().round().committee(),
            Self::NoVote(nv) => nv.data().no_vote().data().round().committee(),
            Self::Handover(h) => h.data().handover().data().next(),
            Self::TimeoutCert(c) => c.data().round().committee(),
            Self::HandoverCert(c) => c.data().next(),
        }
    }

    pub fn signing_key(&self) -> Option<&PublicKey> {
        match self {
            Self::Vertex(e) => Some(e.signing_key()),
            Self::Timeout(e) => Some(e.signing_key()),
            Self::NoVote(e) => Some(e.signing_key()),
            Self::Handover(e) => Some(e.signing_key()),
            Self::TimeoutCert(_) | Self::HandoverCert(_) => None,
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

    pub fn is_handover(&self) -> bool {
        matches!(self, Self::Handover(_))
    }

    pub fn is_handover_cert(&self) -> bool {
        matches!(self, Self::HandoverCert(_))
    }
}

impl<T: Committable> Message<T, Unchecked> {
    pub fn validated<const N: usize>(self, cc: &CommitteeVec<N>) -> Option<Message<T, Validated>> {
        match self {
            Self::Vertex(env) => {
                let round = *env.data().round().data();

                // Get the committee of the vertex round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

                // Validate the envelope's signature:
                let Some(env) = env.validated(c) else {
                    warn!("invalid envelope signature");
                    return None;
                };

                let signer = env.signing_key();

                // The signer's position should match the key ID of the vertex:
                if c.get_index(signer) != Some(env.data().source()) {
                    warn!(%signer, source = %env.data().source(), "signer pos != vertex source");
                    return None;
                };

                // Validate the round signature:
                if !env.data().round().is_valid(c) {
                    warn!(%signer, "invalid round signature");
                    return None;
                }

                // The signer of the envelope should also be the same as the one who signed
                // the round number certificate:
                if signer != env.data().round().signing_key() {
                    warn!(
                        %signer,
                        round = %env.data().round().signing_key(),
                        "envelope signer != vertex round signer"
                    );
                    return None;
                }

                // Validate the previous round evidence:
                if !env.data().evidence().is_valid(round.num(), cc) {
                    warn!(%signer, "invalid evidence in vertex");
                    return None;
                }

                // The following check does not apply to the genesis round or after handover:
                if !(round.num().is_genesis() || env.data().is_first_after_handover()) {
                    // The number of vertex edges must be >= to the committee quorum:
                    if env.data().num_edges() < c.quorum_size().get() {
                        warn!(%signer, "vertex has not enough edges");
                        return None;
                    }
                }

                // No-vote certificate validation:
                if let Some(cert) = env.data().no_vote_cert() {
                    if !cert.is_valid_par(c) {
                        warn!(%signer, "invalid no-vote certificate in vertex");
                        return None;
                    }
                    // The no-vote certificate should apply to the immediate predecessor
                    // of the current vertex round:
                    if cert.data().round().num() + 1 != round.num() {
                        warn!(%signer, "no-vote certificate in vertex applies to invalid round");
                        return None;
                    }
                }

                Some(Message::Vertex(env))
            }
            Self::Timeout(e) => {
                let round = e.data().timeout().data().round();

                // Get the committee of the timeout round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

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
                if !e.data().evidence().is_valid(round.num(), cc) {
                    warn!(%signer, "invalid timeout evidence");
                    return None;
                }

                Some(Message::Timeout(e))
            }
            Self::NoVote(e) => {
                let round = e.data().no_vote().data().round();

                // Get the committee of the no-vote round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

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
                if round != e.data().certificate().data().round() {
                    warn!(%signer, "no-vote certificate applies to invalid round");
                    return None;
                }

                Some(Message::NoVote(e))
            }
            Self::Handover(env) => {
                let round = env.data().handover().data().round();

                // Get the committee of the handover round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

                // Validate the envelope's signature:
                let Some(env) = env.validated(c) else {
                    warn!("invalid envelope signature");
                    return None;
                };

                let signer = env.signing_key();

                // The signer should be the producer of the handover message:
                if signer != env.data().handover().signing_key() {
                    warn!(
                        %signer,
                        handover = %env.data().handover().signing_key(),
                        "envelope signer != handover signer"
                    );
                    return None;
                }

                // Validate evidence of this handover message.
                let Evidence::Regular(evi) = env.data().evidence() else {
                    warn!(%signer, "unexpected handover evidence");
                    return None;
                };
                if evi.data() != &round || !evi.is_valid_par(c) {
                    warn!(%signer, "invalid handover evidence");
                    return None;
                }

                Some(Message::Handover(env))
            }
            Self::TimeoutCert(crt) => {
                let round = crt.data().round();

                // Get the committee of the certificate round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

                // Validate the timeout certificate signatures:
                if !crt.is_valid_par(c) {
                    warn!("invalid timeout certificate");
                    return None;
                }

                Some(Message::TimeoutCert(crt))
            }
            Self::HandoverCert(crt) => {
                let round = crt.data().round();

                // Get the committee of the certificate round.
                let Some(c) = cc.get(round.committee()) else {
                    warn!(%round, "committee not found");
                    return None;
                };

                // Validate the handover certificate signatures:
                if !crt.is_valid_par(c) {
                    warn!("invalid handover certificate");
                    return None;
                }

                Some(Message::HandoverCert(crt))
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Payload<T: Committable> {
    round: Round,
    source: KeyId,
    data: T,
    evidence: Evidence,
}

impl<T: Committable> Payload<T> {
    pub fn new(round: Round, source: KeyId, data: T, evidence: Evidence) -> Self {
        Self {
            round,
            source,
            data,
            evidence,
        }
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn source(&self) -> KeyId {
        self.source
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn into_data(self) -> T {
        self.data
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn into_evidence(self) -> Evidence {
        self.evidence
    }

    pub fn into_parts(self) -> (Round, KeyId, T, Evidence) {
        (self.round, self.source, self.data, self.evidence)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Action<T: Committable> {
    /// Reset the timer to the given round.
    ResetTimer(Round),

    /// Deliver payload data to the application layer.
    Deliver(Payload<T>),

    /// Send a vertex proposal to all nodes.
    SendProposal(Envelope<Vertex<T>, Validated>),

    /// Send a timeout message to all nodes.
    SendTimeout(Envelope<TimeoutMessage, Validated>),

    /// Send a handover message to all nodes of the next committee.
    SendHandover(Envelope<HandoverMessage, Validated>),

    /// Send a no-vote message to the given node.
    SendNoVote(PublicKey, Envelope<NoVoteMessage, Validated>),

    /// Send a timeout certificate to all nodes.
    SendTimeoutCert(Certificate<Timeout>),

    /// Send a handover certificate to all nodes of the next committee.
    SendHandoverCert(Certificate<Handover>),

    /// Are we in catchup?
    Catchup(Round),

    /// Signal that it is safe to garbage collect up to the given round number.
    Gc(Round),

    /// Use a committee starting at the given round.
    UseCommittee(Round),

    /// A minority node detected that the quorum has restarted.
    ///
    /// This action indicates that this node should restart asap to
    /// join the quorum in processing.
    RestartRequired,
}

impl<T: Committable> Action<T> {
    pub fn is_deliver(&self) -> bool {
        matches!(self, Self::Deliver(_))
    }
}

impl<T: Committable> fmt::Display for Action<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::ResetTimer(round) => write!(f, "ResetTimer({round})"),
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
            Action::SendHandover(envelope) => {
                write!(
                    f,
                    "SendHandover({})",
                    envelope.data().handover().data().round()
                )
            }
            Action::SendNoVote(ver_key, envelope) => {
                write!(
                    f,
                    "SendNoVote({ver_key}, {})",
                    envelope.data().no_vote().data().round()
                )
            }
            Action::SendTimeoutCert(certificate) => {
                write!(f, "SendTimeoutCert({})", certificate.data().round())
            }
            Action::SendHandoverCert(certificate) => {
                write!(f, "SendHandoverCert({})", certificate.data().round())
            }
            Action::Gc(r) => {
                write!(f, "Gc({r})")
            }
            Action::Catchup(r) => {
                write!(f, "Catchup({r})")
            }
            Action::UseCommittee(r) => {
                write!(f, "UseCommittee({r})")
            }
            Action::RestartRequired => f.write_str("RestartRequired"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct Timeout {
    round: Round,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct NoVote {
    round: Round,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct Handover {
    round: Round,
    next: CommitteeId,
}

impl Timeout {
    pub fn new(r: Round) -> Self {
        Self { round: r }
    }

    pub fn round(&self) -> Round {
        self.round
    }
}

impl NoVote {
    pub fn new(r: Round) -> Self {
        Self { round: r }
    }

    pub fn round(&self) -> Round {
        self.round
    }
}

impl Handover {
    pub fn new(r: Round, c: CommitteeId) -> Self {
        Self { round: r, next: c }
    }

    pub fn round(&self) -> Round {
        self.round
    }

    pub fn next(&self) -> CommitteeId {
        self.next
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Evidence {
    Genesis,
    Regular(Certificate<Round>),
    Timeout(Certificate<Timeout>),
    Handover(Certificate<Handover>),
}

impl Evidence {
    pub fn round(&self) -> RoundNumber {
        match self {
            Self::Genesis => GENESIS_ROUND,
            Self::Regular(x) => x.data().num(),
            Self::Timeout(x) => x.data().round().num(),
            Self::Handover(x) => x.data().round().num(),
        }
    }

    pub fn is_valid<const N: usize>(&self, r: RoundNumber, cc: &CommitteeVec<N>) -> bool {
        match self {
            Self::Genesis => r.is_genesis(),
            Self::Regular(x) => {
                let Some(c) = cc.get(x.data().committee()) else {
                    return false;
                };
                self.round() + 1 == r && x.is_valid_par(c)
            }
            Self::Timeout(x) => {
                let Some(c) = cc.get(x.data().round().committee()) else {
                    return false;
                };
                self.round() + 1 == r && x.is_valid_par(c)
            }
            Self::Handover(x) => {
                let Some(c) = cc.get(x.data().round().committee()) else {
                    return false;
                };
                self.round() + 1 == r && x.is_valid_par(c)
            }
        }
    }

    pub fn is_genesis(&self) -> bool {
        matches!(self, Self::Genesis)
    }

    pub fn is_regular(&self) -> bool {
        matches!(self, Self::Regular(_))
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(_))
    }

    pub fn is_handover(&self) -> bool {
        matches!(self, Self::Handover(_))
    }
}

impl From<Certificate<Round>> for Evidence {
    fn from(value: Certificate<Round>) -> Self {
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
    pub fn new(c: CommitteeId, e: Evidence, k: &Keypair) -> Self {
        let r = Round::new(
            if e.is_genesis() {
                e.round()
            } else {
                e.round() + 1
            },
            c,
        );
        Self {
            timeout: Signed::new(Timeout::new(r), k),
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
    pub fn new(e: Certificate<Timeout>, k: &Keypair) -> Self {
        Self {
            no_vote: Signed::new(NoVote::new(e.data().round), k),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct HandoverMessage {
    handover: Signed<Handover>,
    evidence: Evidence,
}

impl HandoverMessage {
    pub fn new(h: Handover, e: Evidence, k: &Keypair) -> Self {
        Self {
            handover: Signed::new(h, k),
            evidence: e,
        }
    }

    pub fn handover(&self) -> &Signed<Handover> {
        &self.handover
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn into_parts(self) -> (Signed<Handover>, Evidence) {
        (self.handover, self.evidence)
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
                write!(f, "TimeoutCert({})", c.data().round())
            }
            Self::Handover(h) => {
                write!(f, "Handover({})", h.data().handover().data())
            }
            Self::HandoverCert(c) => {
                write!(f, "HandoverCert({})", c.data().round())
            }
        }
    }
}

impl fmt::Display for Handover {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ committee := {}, next := {}, round := {} }}",
            self.round.committee(),
            self.next,
            self.round.num()
        )
    }
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaderThresholdReached(r) => write!(f, "LeaderThresholdReached({r})"),
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

impl Committable for Handover {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Handover")
            .field("round", self.round.commit())
            .field("next", self.next.commit())
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

impl Committable for HandoverMessage {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("HandoverMessage")
            .field("handover", self.handover.commit())
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
            Self::Handover(c) => RawCommitmentBuilder::new("Evidence::Handover")
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
            Self::Handover(h) => builder.field("handover", h.commit()).finalize(),
            Self::HandoverCert(c) => builder.field("handover-cert", c.commit()).finalize(),
        }
    }
}

impl<T: Committable> Committable for Payload<T> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Payload")
            .field("round", self.round.commit())
            .fixed_size_field("source", &self.source.to_bytes())
            .field("data", self.data.commit())
            .finalize()
    }
}
