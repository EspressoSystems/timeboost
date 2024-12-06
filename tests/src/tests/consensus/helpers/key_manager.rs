use std::{collections::HashMap, sync::Arc};

use committable::Committable;
use multisig::{Committee, Envelope, Keypair, PublicKey, Validated};
use sailfish::consensus::{Consensus, Dag};
use timeboost_core::types::{
    message::{Message, Timeout},
    metrics::SailfishMetrics,
    vertex::Vertex,
    NodeId,
};
use timeboost_utils::types::round_number::RoundNumber;
use timeboost_utils::unsafe_zero_keypair;

use super::node_instrument::TestNodeInstrument;

pub struct KeyManager {
    keys: HashMap<u64, Keypair>,
}

impl KeyManager {
    pub(crate) fn new(num_nodes: u64) -> Self {
        let key_pairs = (0..num_nodes).map(unsafe_zero_keypair).collect::<Vec<_>>();
        Self {
            keys: key_pairs
                .iter()
                .enumerate()
                .map(|(id, kpair)| (id as u64, kpair.clone()))
                .collect(),
        }
    }

    pub(crate) fn create_node_instruments(&self) -> Vec<TestNodeInstrument> {
        let committee = Committee::new(self.keys.iter().map(|(i, k)| (*i as u8, k.public_key())));
        let metrics = Arc::new(SailfishMetrics::default());
        self.keys
            .iter()
            .map(|(id, kpair)| {
                let node_id = NodeId::from(*id);
                TestNodeInstrument::new(
                    Consensus::new(node_id, kpair.clone(), committee.clone())
                        .with_metrics(metrics.clone()),
                )
            })
            .collect()
    }

    pub(crate) fn create_timeout_vote_msg(&self, round: RoundNumber) -> Vec<Message> {
        self.keys
            .values()
            .map(|kpair| {
                let d = Timeout::new(round);
                let e = Envelope::deterministically_signed(d, kpair);
                Message::Timeout(e)
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
        let mut v = Vertex::new(round, kpair.public_key());
        v.add_edges(edges);
        let e = Envelope::deterministically_signed(v, kpair);
        Message::Vertex(e)
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
        let e = Envelope::deterministically_signed(t, kpair);
        Message::Timeout(e)
    }

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

    pub(crate) fn signers<T>(&self, value: T, count: usize) -> Vec<Envelope<T, Validated>>
    where
        T: Committable + Clone,
    {
        let mut envs = Vec::new();
        for kpair in self.keys.values().take(count) {
            envs.push(Envelope::deterministically_signed(value.clone(), kpair))
        }
        envs
    }

    pub(crate) fn prepare_dag(&self, round: u64, committee: &Committee) -> (Dag, Vec<PublicKey>) {
        let mut dag = Dag::new(committee.size());
        let edges = self
            .keys
            .values()
            .map(|kpair| {
                let v = Vertex::new(round, kpair.public_key());
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
        let d = Vertex::new(round, kpair.public_key());
        let e = Envelope::deterministically_signed(d, kpair);
        Message::Vertex(e)
    }
}
