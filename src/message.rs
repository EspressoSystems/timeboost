use crate::{
    certificate::Certificate,
    timeout::{NoVoteData, TimeoutData},
    BLSPubKey, SignatureKey,
};
use committable::{Commitment, Committable};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct RoundNumber(u64);

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
    pub no_vote_certificate: Option<Certificate<NoVoteData>>,

    /// The timeout certificate for `v.round - 1`.
    pub timeout_certificate: Option<Certificate<TimeoutData>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    header: BlockHeader,
    payload: Vec<u8>,
}

pub struct Vertex {
    /// The round of the vertex $v$ in the DAG.
    round: RoundNumber,

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
pub enum SailfishMessage {
    Vertex(),
    Timeout(),
    NoVote(),
}
