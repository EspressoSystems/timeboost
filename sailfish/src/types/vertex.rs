use std::{collections::BTreeSet, fmt::Display};

use committable::Committable;
use hotshot::types::SignatureKey;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use serde::{Deserialize, Serialize};

use super::{block::Block, certificate::Certificate, message::{NoVote, Timeout}, PublicKey};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VertexId {
    round: ViewNumber,
    source: PublicKey,
}

impl VertexId {
    pub fn round(&self) -> ViewNumber {
        self.round
    }

    pub fn source(&self) -> &PublicKey {
        &self.source
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Vertex {
    id: VertexId,
    block: Block,
    strong: BTreeSet<VertexId>,
    weak: BTreeSet<VertexId>,
    no_vote: Option<Certificate<NoVote>>,
    timeout: Option<Certificate<Timeout>>,
}

impl Vertex {
    pub fn genesis(source: PublicKey) -> Self {
        Self {
            id: VertexId {
                round: ViewNumber::genesis(),
                source
            },
            block: Block::empty(),
            strong: BTreeSet::new(),
            weak: BTreeSet::new(),
            no_vote: None,
            timeout: None,
        }
    }

    pub fn id(&self) -> &VertexId {
        &self.id
    }

    /// Does this vertex have a strong (direct) connection to the given `VertexId`?
    pub fn has_strong(&self, id: &VertexId) -> bool {
        self.strong.contains(id)
    }

    /// Does this vextex have a weak (indirect) connection to the given `VertexId`?
    pub fn has_weak(&self, id: &VertexId) -> bool {
        self.weak.contains(id)
    }
}

impl Display for VertexId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VertexId {{ round := {}, source := {} }}", self.round, self.source)
    }
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex {{ id := {} }}", self.id)
    }
}

impl Committable for VertexId {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("VertexId")
            .field("round", self.round.commit())
            .var_size_field("source", &self.source.to_bytes())
            .finalize()
    }
}

impl Committable for Vertex {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Vertex")
            .field("id", self.id.commit())
            .field("block", self.block.commit())
            .array_field(
                "strong",
                &self.strong.iter().map(|p| p.commit()).collect::<Vec<_>>(),
            )
            .array_field(
                "weak",
                &self.weak.iter().map(|p| p.commit()).collect::<Vec<_>>(),
            )
            .optional("no_vote", &self.no_vote)
            .optional("timeout", &self.timeout)
            .finalize()
    }
}
