use std::fmt::Display;

use committable::Committable;
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::{data::ViewNumber, simple_certificate::QuorumCertificate};
use serde::{Deserialize, Serialize};

use crate::impls::sailfish_types::SailfishTypes;

use super::{
    block::Block,
    certificate::{NoVoteCertificate, TimeoutCertificate},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Vertex {
    /// The round of the vertex $v$ in the DAG.
    pub round: ViewNumber,

    /// The source that broadcasted this vertex $v$
    source: BLSPubKey,

    /// The block of transactions being transmitted
    block: Block,

    /// The parents to this vertex (the 2f + 1 vertices from round r - 1)
    parents: Vec<QuorumCertificate<SailfishTypes>>,

    /// The no-vote certificate for `v.round - 1`.
    pub no_vote_certificate: Option<NoVoteCertificate>,

    /// The timeout certificate for `v.round - 1`.
    pub timeout_certificate: Option<TimeoutCertificate>,
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex(round: {}, source: {})", self.round, self.source)
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
                &self.parents.iter().map(|p| p.commit()).collect::<Vec<_>>(),
            )
            .optional("no_vote_certificate", &self.no_vote_certificate)
            .optional("timeout_certificate", &self.timeout_certificate)
            .finalize()
    }
}
