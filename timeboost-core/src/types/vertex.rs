use std::{collections::BTreeSet, fmt::Display, hash::Hash};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use timeboost_crypto::traits::signature_key::SignatureKey;
use timeboost_utils::types::round_number::RoundNumber;

use super::{
    certificate::Certificate,
    message::{NoVote, Timeout},
    PublicKey,
};
use crate::types::block::Block;
use crate::types::Label;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, FromRow)]
pub struct Vertex {
    source: PublicKey,
    round: RoundNumber,
    edges: BTreeSet<PublicKey>,
    no_vote: Option<Certificate<NoVote>>,
    timeout: Option<Certificate<Timeout>>,
    block: Block,
}

impl Vertex {
    pub fn new<N: Into<RoundNumber>>(r: N, s: PublicKey) -> Self {
        Self {
            source: s,
            round: r.into(),
            edges: BTreeSet::new(),
            no_vote: None,
            timeout: None,
            block: Block::empty(),
        }
    }

    pub fn source(&self) -> &PublicKey {
        &self.source
    }

    pub fn round(&self) -> RoundNumber {
        self.round
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

    pub fn set_timeout(&mut self, t: Certificate<Timeout>) -> &mut Self {
        self.timeout = Some(t);
        self
    }

    pub fn dbg_edges(&self) {
        println! { "{} -> {} -> {:?}",
            Label::new(self.source()),
            self.round(),
            self.edges().map(Label::new).collect::<Vec<_>>()
        }
    }
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vertex {{ round := {}, source := {} }}",
            self.round, self.source
        )
    }
}

impl Committable for Vertex {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Vertex")
            .var_size_field("source", &self.source.to_bytes())
            .field("round", self.round.commit())
            .field("block", self.block.commit())
            .optional("no_vote", &self.no_vote)
            .optional("timeout", &self.timeout)
            .u64_field("edges", self.edges.len() as u64);
        self.edges
            .iter()
            .fold(builder, |b, e| b.var_size_bytes(&e.to_bytes()))
            .finalize()
    }
}
