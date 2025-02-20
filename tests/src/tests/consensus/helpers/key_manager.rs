use std::collections::BTreeMap;

use committable::Committable;
use multisig::{
    Certificate, Committee, Envelope, Keypair, PublicKey, Signed, Validated, VoteAccumulator,
};
use sailfish::consensus::ConsensusMetrics;
use sailfish::types::{Evidence, RoundNumber, Timeout, TimeoutMessage};
use timeboost_utils::unsafe_zero_keypair;

use super::node_instrument::TestNodeInstrument;
use crate::prelude::*;

#[derive(Clone)]
pub struct KeyManager {
    keys: BTreeMap<u8, Keypair>,
    committee: Committee,
}

/// Helper for all the keys in a committeee for testing purposes.
impl KeyManager {
    pub(crate) fn new(num_nodes: u8) -> Self {
        let key_pairs = (0..num_nodes).map(|i| (i, unsafe_zero_keypair(i as u64)));
        let committee = Committee::new(key_pairs.clone().map(|(i, k)| (i, k.public_key())));
        Self {
            keys: key_pairs.collect(),
            committee,
        }
    }

    /// Create test helpers for all the nodes.
    pub(crate) fn create_node_instruments(&self) -> Vec<TestNodeInstrument> {
        self.keys
            .values()
            .map(|kpair| {
                let metrics = ConsensusMetrics::default();
                let cons =
                    Consensus::new(kpair.clone(), self.committee.clone()).with_metrics(metrics);
                TestNodeInstrument::new(self.clone(), kpair.clone(), cons)
            })
            .collect()
    }

    /// For a given round create vertex message for each node in committee.
    pub(crate) fn create_vertex_msgs(&self, round: u64, edges: Vec<PublicKey>) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_vertex_msg_for_node_id(*id, round, edges.clone()))
            .collect()
    }

    /// For a given round create vertex message for a given node in the committee
    /// and add the edges to public keys.
    pub(crate) fn create_vertex_msg_for_node_id(
        &self,
        id: u8,
        round: u64,
        edges: Vec<PublicKey>,
    ) -> Message {
        let kpair = &self.keys[&id];
        let mut v = Vertex::empty(round, self.gen_round_cert(round - 1), kpair, true);
        v.add_edges(edges);
        let e = Envelope::signed(v, kpair, true);
        Message::Vertex(e)
    }

    /// For a given round, create a timeout message for all nodes in committee.
    pub(crate) fn create_timeout_msgs(&self, round: u64) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_timeout_msg_for_node_id(*id, round))
            .collect()
    }

    /// For a given round, create a timeout message for specified node id in committee.
    pub(crate) fn create_timeout_msg_for_node_id(&self, id: u8, round: u64) -> Message {
        let kpair = &self.keys[&id];
        let t = TimeoutMessage::new(self.gen_round_cert(round - 1).into(), kpair, true);
        let e = Envelope::signed(t, kpair, true);
        Message::Timeout(e)
    }

    /// Get vertex edges for a round.
    pub(crate) fn edges_for_round(
        &self,
        round: RoundNumber,
        committee: &Committee,
        ignore_leader: bool,
    ) -> Vec<PublicKey> {
        // 2f + 1 edges
        let threshold = committee.quorum_size().get();
        let leader = committee.leader(*round as usize);
        self.keys
            .values()
            .map(|kpair| kpair.public_key())
            .filter(|pub_key| !ignore_leader || *pub_key != leader)
            .take(threshold)
            .collect()
    }

    /// Create an envelope with signers for given type.
    pub(crate) fn signers<T>(&self, value: T, count: usize) -> Vec<Envelope<T, Validated>>
    where
        T: Committable + Clone,
    {
        let mut envs = Vec::new();
        for kpair in self.keys.values().take(count) {
            envs.push(Envelope::signed(value.clone(), kpair, true))
        }
        envs
    }

    /// Setup dag for testing.
    pub(crate) fn prepare_dag(
        &self,
        round: u64,
        committee: &Committee,
    ) -> (Dag, Evidence, Vec<PublicKey>) {
        let mut dag = Dag::new(committee.size());
        let edges = self
            .keys
            .values()
            .map(|kpair| {
                let v = Vertex::empty(round, self.gen_round_cert(round - 1), kpair, true);
                dag.add(v.clone());
                *v.source()
            })
            .collect();
        let evidence = Evidence::Regular(self.gen_round_cert(round));
        (dag, evidence, edges)
    }

    /// Craft a vertex message for a given round and keypair.
    pub(crate) fn create_vertex_proposal_msg(
        &self,
        round: RoundNumber,
        kpair: &Keypair,
    ) -> Message {
        let d = Vertex::empty(round, self.gen_round_cert(round - 1), kpair, true);
        let e = Envelope::signed(d, kpair, true);
        Message::Vertex(e)
    }

    /// Craft a timeout certificate with signers from committee.
    pub(crate) fn gen_timeout_cert<N: Into<RoundNumber>>(&self, r: N) -> Certificate<Timeout> {
        let mut va = VoteAccumulator::new(self.committee.clone());
        let r = r.into();
        for k in self.keys.values() {
            va.add(Signed::new(Timeout::new(r), k, true)).unwrap();
        }
        va.into_certificate().unwrap()
    }

    /// Craft a timeout certificate with signers from committee.
    pub(crate) fn gen_round_cert<N: Into<RoundNumber>>(&self, r: N) -> Certificate<RoundNumber> {
        let mut va = VoteAccumulator::new(self.committee.clone());
        let r = r.into();
        for k in self.keys.values() {
            va.add(Signed::new(r, k, true)).unwrap();
        }
        va.into_certificate().unwrap()
    }

    pub(crate) fn committee(&self) -> Committee {
        self.committee.clone()
    }
}
