use std::{collections::BTreeSet, fmt::Display, hash::Hash};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use hotshot::types::SignatureKey;
use serde::{Deserialize, Serialize};

use super::{
    certificate::Certificate,
    message::{Evidence, NoVote},
    PublicKey,
};
use crate::types::Keypair;
use crate::types::{block::Block, round_number::RoundNumber, signed::Signed};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Vertex {
    source: PublicKey,
    round: Signed<RoundNumber>,
    edges: BTreeSet<PublicKey>,
    evidence: Evidence,
    no_vote: Option<Certificate<NoVote>>,
    block: Block,
}

impl Vertex {
    pub fn new<N, E>(r: N, e: E, k: &Keypair) -> Self
    where
        N: Into<RoundNumber>,
        E: Into<Evidence>,
    {
        let r = r.into();
        let e = e.into();
        // debug_assert!(e.round() + 1 == r || r == RoundNumber::genesis());
        Self {
            source: *k.public_key(),
            round: Signed::new(r, k),
            edges: BTreeSet::new(),
            evidence: e,
            no_vote: None,
            block: Block::empty(),
        }
    }

    pub fn is_genesis(&self) -> bool {
        *self.round.data() == RoundNumber::genesis()
            && *self.round.data() == self.evidence.round()
            && self.edges.is_empty()
            && self.no_vote.is_none()
            && self.block.is_empty()
    }

    pub fn source(&self) -> &PublicKey {
        &self.source
    }

    pub fn round(&self) -> &Signed<RoundNumber> {
        &self.round
    }

    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    pub fn edges(&self) -> impl Iterator<Item = &PublicKey> {
        self.edges.iter()
    }

    pub fn has_edge(&self, id: &PublicKey) -> bool {
        self.edges.contains(id)
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
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

    pub fn add_edge(&mut self, id: PublicKey) -> &mut Self {
        self.edges.insert(id);
        self
    }

    pub fn add_edges<I>(&mut self, edges: I) -> &mut Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.edges.extend(edges);
        self
    }

    pub fn set_no_vote(&mut self, n: Certificate<NoVote>) -> &mut Self {
        self.no_vote = Some(n);
        self
    }
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vertex {{ round := {}, source := {} }}",
            self.round.data(),
            self.source
        )
    }
}

impl Committable for Vertex {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Vertex")
            .var_size_field("source", &self.source.to_bytes())
            .field("round", self.round.commit())
            .field("block", self.block.commit())
            .field("evidence", self.evidence.commit())
            .optional("no_vote", &self.no_vote)
            .u64_field("edges", self.edges.len() as u64);
        self.edges
            .iter()
            .fold(builder, |b, e| b.var_size_bytes(&e.to_bytes()))
            .finalize()
    }
}
