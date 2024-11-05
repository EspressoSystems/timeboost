use std::collections::HashMap;

use sailfish::consensus::{Consensus, Dag};
use timeboost_core::types::{
    committee::StaticCommittee,
    envelope::Envelope,
    message::{Message, Timeout},
    round_number::RoundNumber,
    vertex::Vertex,
    Keypair, NodeId, PublicKey,
};

use super::node_instrument::TestNodeInstrument;

pub struct KeyManager {
    keys: HashMap<u64, Keypair>,
}

impl KeyManager {
    pub(crate) fn new(num_nodes: u64) -> Self {
        let key_pairs = (0..num_nodes).map(Keypair::new).collect::<Vec<_>>();
        Self {
            keys: key_pairs
                .iter()
                .enumerate()
                .map(|(id, kpair)| (id as u64, kpair.clone()))
                .collect(),
        }
    }

    pub(crate) fn create_node_instruments(&self) -> Vec<TestNodeInstrument> {
        let committee = StaticCommittee::new(
            self.keys
                .values()
                .map(|kpair| *kpair.public_key())
                .collect(),
        );
        self.keys
            .iter()
            .map(|(id, kpair)| {
                let node_id = NodeId::from(*id);
                TestNodeInstrument::new(Consensus::new(node_id, kpair.clone(), committee.clone()))
            })
            .collect()
    }

    pub(crate) fn create_timeout_vote_msg(&self, round: RoundNumber) -> Vec<Message> {
        self.keys
            .values()
            .map(|kpair| {
                let d = Timeout::new(round);
                let e = Envelope::signed(d, kpair);
                Message::Timeout(e.cast())
            })
            .collect()
    }

    pub(crate) fn create_vertex_msgs(&self, round: u64, edges: Vec<PublicKey>) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_vertex_msg_for_node_id(id, round, edges.clone()))
            .collect()
    }

    pub(crate) fn create_vertex_msg_for_node_id(
        &self,
        id: &u64,
        round: u64,
        edges: Vec<PublicKey>,
    ) -> Message {
        let kpair = self.keys.get(id).unwrap();
        let mut v = Vertex::new(RoundNumber::new(round), *kpair.public_key());
        v.add_edges(edges);
        let e = Envelope::signed(v, kpair);
        Message::Vertex(e.cast())
    }

    pub(crate) fn create_timeout_msgs(&self, round: u64) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_timeout_msg_for_node_id(id, round))
            .collect()
    }

    pub(crate) fn create_timeout_msg_for_node_id(&self, id: &u64, round: u64) -> Message {
        let kpair = self.keys.get(id).unwrap();
        let t = Timeout::new(RoundNumber::new(round));
        let e = Envelope::signed(t, kpair);
        Message::Timeout(e.cast())
    }

    pub(crate) fn prepare_dag(
        &self,
        round: u64,
        committee: &StaticCommittee,
    ) -> (Dag, Vec<PublicKey>) {
        let mut dag = Dag::new(committee.size());
        let edges = self
            .keys
            .values()
            .map(|kpair| {
                let v = Vertex::new(RoundNumber::new(round), *kpair.public_key());
                dag.add(v.clone());
                *v.source()
            })
            .collect();

        (dag, edges)
    }

    pub(crate) fn create_vertex_proposal_msg(
        &self,
        round: RoundNumber,
        kpair: &Keypair,
    ) -> Message {
        let d = Vertex::new(round, *kpair.public_key());
        let e = Envelope::signed(d, kpair);
        Message::Vertex(e.cast())
    }
}
