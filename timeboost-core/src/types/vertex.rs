use std::{collections::BTreeSet, fmt::Display};

use committable::Committable;
use hotshot::types::SignatureKey;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use serde::{Deserialize, Serialize};

use super::{
    certificate::Certificate,
    message::{NoVote, Timeout},
    PublicKey,
};
use crate::types::block::Block;

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
    pub fn new(r: ViewNumber, s: PublicKey) -> Self {
        Self {
            id: VertexId {
                round: r,
                source: s,
            },
            block: Block::empty(),
            strong: BTreeSet::new(),
            weak: BTreeSet::new(),
            no_vote: None,
            timeout: None,
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.id.round == ViewNumber::genesis()
            && self.block.is_empty()
            && self.strong.is_empty()
            && self.weak.is_empty()
            && self.no_vote.is_none()
            && self.timeout.is_none()
    }

    pub fn id(&self) -> &VertexId {
        &self.id
    }

    pub fn round(&self) -> ViewNumber {
        self.id.round
    }

    pub fn source(&self) -> &PublicKey {
        &self.id.source
    }

    pub fn edge_count(&self) -> usize {
        self.strong_edge_count() + self.weak_edge_count()
    }

    pub fn strong_edge_count(&self) -> usize {
        self.strong.len()
    }

    pub fn weak_edge_count(&self) -> usize {
        self.weak.len()
    }

    pub fn strong_edges(&self) -> impl Iterator<Item = &VertexId> {
        self.strong.iter()
    }

    pub fn weak_edges(&self) -> impl Iterator<Item = &VertexId> {
        self.weak.iter()
    }

    pub fn edges(&self) -> impl Iterator<Item = &VertexId> {
        self.strong_edges().chain(self.weak_edges())
    }

    /// Does this vertex have a strong (direct) connection to the given `VertexId`?
    pub fn has_strong_edge(&self, id: &VertexId) -> bool {
        self.strong.contains(id)
    }

    /// Does this vextex have a weak (indirect) connection to the given `VertexId`?
    pub fn has_weak_edge(&self, id: &VertexId) -> bool {
        self.weak.contains(id)
    }

    pub fn timeout_cert(&self) -> Option<&Certificate<Timeout>> {
        self.timeout.as_ref()
    }

    pub fn no_vote_cert(&self) -> Option<&Certificate<NoVote>> {
        self.no_vote.as_ref()
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn set_block(&mut self, b: Block) -> &mut Self {
        self.block = b;
        self
    }

    pub fn add_strong_edge(&mut self, e: VertexId) -> &mut Self {
        self.strong.insert(e);
        self
    }

    pub fn add_weak_edge(&mut self, e: VertexId) -> &mut Self {
        self.weak.insert(e);
        self
    }

    pub fn add_strong_edges<I>(&mut self, e: I) -> &mut Self
    where
        I: IntoIterator<Item = VertexId>,
    {
        self.strong.extend(e);
        self
    }

    pub fn add_weak_edges<I>(&mut self, e: I) -> &mut Self
    where
        I: IntoIterator<Item = VertexId>,
    {
        self.weak.extend(e);
        self
    }

    pub fn set_no_vote(&mut self, n: Certificate<NoVote>) -> &mut Self {
        self.no_vote = Some(n);
        self
    }

    pub fn set_timeout(&mut self, t: Certificate<Timeout>) -> &mut Self {
        self.timeout = Some(t);
        self
    }
}

impl Display for VertexId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VertexId {{ round := {}, source := {} }}",
            self.round, self.source
        )
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
