use std::fmt::Display;

use crate::certificate::{NoVoteCertificate, TimeoutCertificate};
use committable::{Commitment, Committable};
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_task::task::TaskEvent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct RoundNumber(u64);

impl Display for RoundNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Committable for RoundNumber {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("RoundNumber")
            .u64(self.0)
            .finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub author: BLSPubKey,

    /// The round number of the block.
    pub round: RoundNumber,

    /// The signature of the block.
    pub signature: <BLSPubKey as SignatureKey>::QcType,

    /// The no-vote certificate for `v.round - 1`.
    pub no_vote_certificate: Option<NoVoteCertificate>,

    /// The timeout certificate for `v.round - 1`.
    pub timeout_certificate: Option<TimeoutCertificate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    header: BlockHeader,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vertex {
    /// The round of the vertex $v$ in the DAG.
    pub round: RoundNumber,

    /// The source that broadcasted this vertex $v$
    source: BLSPubKey,

    /// The block of transactions being transmitted
    block: Block,

    /// The at-least `2f + 1` vertices from round `r - 1`.
    strong_edges: u64,

    /// The up-to `f` vertices from round < `r - 1` such that there is no path
    /// from `v` to these vertices.
    weak_edges: u64,
}

#[derive(Eq, PartialEq, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum SailfishMessage {
    Shutdown,
    Vertex(Vertex),
    Timeout(TimeoutCertificate),
    NoVote(NoVoteCertificate),
}

impl TaskEvent for SailfishMessage {
    fn shutdown_event() -> Self {
        SailfishMessage::Shutdown
    }
}

impl Display for SailfishMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SailfishMessage::Vertex(v) => write!(f, "Vertex({})", v.round),
            SailfishMessage::Timeout(timeout) => write!(f, "Timeout({})", timeout.round_number()),
            SailfishMessage::NoVote(no_vote) => write!(f, "NoVote({})", no_vote.round_number()),
            SailfishMessage::Shutdown => write!(f, "Shutdown"),
        }
    }
}
