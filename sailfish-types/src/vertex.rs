use std::{collections::BTreeSet, fmt::Display, hash::Hash};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, KeyId, Keypair, PublicKey, Signed};
use serde::{Deserialize, Serialize};

use crate::{Evidence, NoVote, Round, RoundNumber};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vertex<T> {
    round: Signed<Round>,
    source: (KeyId, PublicKey),
    edges: BTreeSet<KeyId>,
    evidence: Evidence,
    no_vote: Option<Certificate<NoVote>>,
    committed: RoundNumber,
    payload: T,
}

impl<T> Vertex<T> {
    pub fn new<E>(round: Round, evidence: E, payload: T, key_id: KeyId, keypair: &Keypair) -> Self
    where
        E: Into<Evidence>,
    {
        let evidence = evidence.into();

        debug_assert!(evidence.round() + 1 == round.num() || round.num() == RoundNumber::genesis());

        Self {
            source: (key_id, keypair.public_key()),
            round: Signed::new(round, keypair),
            edges: BTreeSet::new(),
            evidence,
            no_vote: None,
            committed: RoundNumber::genesis(),
            payload,
        }
    }

    /// Is this vertex from the genesis round?
    pub fn is_genesis(&self) -> bool {
        self.round.data().num() == RoundNumber::genesis()
            && self.round.data().num() == self.evidence.round()
            && self.evidence.is_genesis()
            && self.edges.is_empty()
            && self.no_vote.is_none()
    }

    /// Is this vertex the first after a committee handover?
    pub fn is_first_after_handover(&self) -> bool {
        let Evidence::Handover(cert) = &self.evidence else {
            return false;
        };
        self.round.data().committee() == cert.data().next()
            && self.round.data().num() == cert.data().round().num() + 1
            && self.edges.is_empty()
            && self.no_vote.is_none()
    }

    pub fn source(&self) -> &(KeyId, PublicKey) {
        &self.source
    }

    pub fn round(&self) -> &Signed<Round> {
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

    pub fn edges(&self) -> impl Iterator<Item = &KeyId> {
        self.edges.iter()
    }

    pub fn has_edge(&self, id: &KeyId) -> bool {
        self.edges.contains(id)
    }

    pub fn no_vote_cert(&self) -> Option<&Certificate<NoVote>> {
        self.no_vote.as_ref()
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn set_committed_round<N: Into<RoundNumber>>(&mut self, n: N) -> &mut Self {
        self.committed = n.into();
        self
    }

    pub fn add_edge(&mut self, id: KeyId) -> &mut Self {
        self.edges.insert(id);
        self
    }

    pub fn add_edges<I>(&mut self, edges: I) -> &mut Self
    where
        I: IntoIterator<Item = KeyId>,
    {
        self.edges.extend(edges);
        self
    }

    pub fn set_no_vote(&mut self, n: Certificate<NoVote>) -> &mut Self {
        self.no_vote = Some(n);
        self
    }

    pub fn dbg(&self) -> String {
        format!("{} -> {:?}", self, self.edges().collect::<Vec<_>>())
    }
}

impl<T> Display for Vertex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex({},{})", self.round.data(), self.source.1)
    }
}

impl<T: Committable> Committable for Vertex<T> {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Vertex")
            .field("round", self.round.commit())
            .fixed_size_field("source", &self.source.1.to_bytes())
            .field("evidence", self.evidence.commit())
            .field("committed", self.committed.commit())
            .optional("no_vote", &self.no_vote)
            .field("payload", self.payload.commit())
            .u64_field("edges", self.edges.len() as u64);
        self.edges
            .iter()
            .fold(builder, |b, e| b.var_size_bytes(&e.to_bytes()))
            .finalize()
    }
}
