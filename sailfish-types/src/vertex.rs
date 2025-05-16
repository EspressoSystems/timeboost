use std::{collections::BTreeSet, fmt::Display, hash::Hash};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, Indexed, Keypair, PublicKey, Signed};
use serde::{Deserialize, Serialize};

use crate::{Evidence, NextCommittee, NoVote, RoundNumber, UnixTime};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vertex<T> {
    round: Signed<RoundNumber>,
    source: PublicKey,
    edges: BTreeSet<PublicKey>,
    evidence: Evidence,
    no_vote: Option<Certificate<NoVote>>,
    committed: RoundNumber,
    next_committee: Option<NextCommittee>,
    payload: T,
}

impl<T> Vertex<T> {
    pub fn new<N, E>(r: N, e: E, d: T, k: &Keypair, deterministic: bool) -> Self
    where
        N: Into<RoundNumber>,
        E: Into<Evidence>,
    {
        let r = r.into();
        let e = e.into();

        debug_assert!(e.round() + 1 == r || r == RoundNumber::genesis());

        Self {
            source: k.public_key(),
            round: Signed::new(r, k, deterministic),
            edges: BTreeSet::new(),
            evidence: e,
            no_vote: None,
            committed: RoundNumber::genesis(),
            payload: d,
            next_committee: None,
        }
    }

    /// Is this vertex from the genesis round?
    pub fn is_genesis(&self) -> bool {
        *self.round.data() == RoundNumber::genesis()
            && *self.round.data() == self.evidence.round()
            && self.evidence.is_genesis()
            && self.edges.is_empty()
            && self.no_vote.is_none()
    }

    pub fn source(&self) -> &PublicKey {
        &self.source
    }

    pub fn round(&self) -> &Signed<RoundNumber> {
        &self.round
    }

    pub fn committed_round(&self) -> RoundNumber {
        self.committed
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
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

    pub fn no_vote_cert(&self) -> Option<&Certificate<NoVote>> {
        self.no_vote.as_ref()
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn next_committee(&self) -> Option<&NextCommittee> {
        self.next_committee.as_ref()
    }

    pub fn set_committed_round<N: Into<RoundNumber>>(&mut self, n: N) -> &mut Self {
        self.committed = n.into();
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

    pub fn set_next_committee(&mut self, t: UnixTime, r: RoundNumber) -> &mut Self {
        self.next_committee = Some(NextCommittee::new(t, r));
        self
    }

    pub fn dbg(&self) -> String {
        format!("{} -> {:?}", self, self.edges().collect::<Vec<_>>())
    }
}

impl<T> Indexed for Vertex<T> {
    type Index = RoundNumber;

    fn index(&self) -> Self::Index {
        *self.round.data()
    }
}

impl<T> Display for Vertex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex({},{})", self.round.data(), self.source)
    }
}

impl<T: Committable> Committable for Vertex<T> {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Vertex")
            .field("round", self.round.commit())
            .fixed_size_field("source", &self.source.as_bytes())
            .field("evidence", self.evidence.commit())
            .field("committed", self.committed.commit())
            .optional("next_committee", &self.next_committee)
            .optional("no_vote", &self.no_vote)
            .field("payload", self.payload.commit())
            .u64_field("edges", self.edges.len() as u64);
        self.edges
            .iter()
            .fold(builder, |b, e| b.var_size_bytes(e.as_slice()))
            .finalize()
    }
}
