use std::fmt::Display;

use committable::Committable;
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use serde::{Deserialize, Serialize};

use super::{
    block::Block,
    certificate::{NoVoteCertificate, TimeoutCertificate, VertexCertificate},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Vertex {
    /// The round of the vertex $v$ in the DAG.
    pub round: ViewNumber,

    /// The source that broadcasted this vertex $v$
    pub source: BLSPubKey,

    /// The block of transactions being transmitted
    pub block: Block,

    /// The parents to this vertex (the 2f + 1 vertices from round r - 1)
    pub strong_edges: Vec<VertexCertificate>,

    /// The weak edges to this vertex (the 2f + 1 vertices from round r - 2)
    pub weak_edges: Vec<VertexCertificate>,

    /// The no-vote certificate for `v.round - 1`.
    pub no_vote_certificate: Option<NoVoteCertificate>,

    /// The timeout certificate for `v.round - 1`.
    pub timeout_certificate: Option<TimeoutCertificate>,
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex(round: {})", self.round)
    }
}

impl Committable for Vertex {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Vertex")
            .field("round", self.round.commit())
            .constant_str("source")
            .var_size_bytes(&self.source.to_bytes())
            .field("block", self.block.commit())
            .array_field(
                "parents",
                &self
                    .strong_edges
                    .iter()
                    .map(|p| p.commit())
                    .collect::<Vec<_>>(),
            )
            .optional("no_vote_certificate", &self.no_vote_certificate)
            .optional("timeout_certificate", &self.timeout_certificate)
            .finalize()
    }
}

impl Vertex {
    pub fn genesis(public_key: BLSPubKey) -> Self {
        Self {
            round: ViewNumber::genesis(),
            source: public_key,
            block: Block::empty(),
            strong_edges: vec![],
            weak_edges: vec![],
            no_vote_certificate: None,
            timeout_certificate: None,
        }
    }
}
