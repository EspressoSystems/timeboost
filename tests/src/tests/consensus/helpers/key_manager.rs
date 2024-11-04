use std::collections::HashMap;

use sailfish::consensus::Consensus;
use timeboost_core::types::{
    committee::StaticCommittee,
    envelope::Envelope,
    message::{Message, Timeout},
    round_number::RoundNumber,
    Keypair, NodeId, PublicKey,
};

use super::{node_instrument::TestNodeInstrument, test_helpers::create_vertex};

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
            .map(|id| self.create_vertex_msgs_for_node_id(id, round, edges.clone()))
            .collect()
    }

    pub(crate) fn create_vertex_msgs_for_node_id(
        &self,
        id: &u64,
        round: u64,
        edges: Vec<PublicKey>,
    ) -> Message {
        let kpair = self.keys.get(id).unwrap();
        let mut v = create_vertex(round, *kpair.public_key());
        v.add_edges(edges);
        let e = Envelope::signed(v, kpair);
        Message::Vertex(e.cast())
    }

    pub(crate) fn add_vertices_to_node(
        &self,
        round: u64,
        node_handle: &mut TestNodeInstrument,
    ) -> Vec<PublicKey> {
        self.keys
            .values()
            .map(|kpair| {
                let v = create_vertex(round, *kpair.public_key());
                node_handle.node_mut().add_vertex_to_dag(v.clone());
                *v.source()
            })
            .collect()
    }

    pub(crate) fn create_vertex_proposal_msg(
        &self,
        round: RoundNumber,
        kpair: &Keypair,
    ) -> Message {
        let d = create_vertex(*round, *kpair.public_key());
        let e = Envelope::signed(d, kpair);
        Message::Vertex(e.cast())
    }
}
