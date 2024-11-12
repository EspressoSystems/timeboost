use std::collections::HashMap;

use super::node_instrument::TestNodeInstrument;
use bitvec::bitvec;
use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use sailfish::consensus::{Consensus, Dag};
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::Envelope,
    message::{Evidence, Message, TimeoutMessage},
    round_number::RoundNumber,
    vertex::Vertex,
    Keypair, NodeId, PublicKey, Signature,
};

pub struct KeyManager {
    keys: HashMap<u64, Keypair>,
}

impl KeyManager {
    pub(crate) fn new(num_nodes: u64) -> Self {
        let keypairs = (0..num_nodes).map(Keypair::new).collect::<Vec<_>>();
        Self {
            keys: keypairs
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

    pub(crate) fn create_timeout_vote_msg(
        &self,
        round: RoundNumber,
        committee: &StaticCommittee,
    ) -> Vec<Message> {
        self.keys
            .values()
            .map(|kpair| {
                let e = self.round_evidence(round - 1, committee);
                let d = TimeoutMessage::new(round, e, kpair);
                let e = Envelope::signed(d, kpair);
                Message::Timeout(e.cast())
            })
            .collect()
    }

    pub(crate) fn create_vertex_msgs(
        &self,
        round: u64,
        edges: Vec<PublicKey>,
        committee: &StaticCommittee,
    ) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_vertex_msg_for_node_id(id, round, edges.clone(), committee))
            .collect()
    }

    pub(crate) fn create_vertex_msg_for_node_id(
        &self,
        id: &u64,
        round: u64,
        edges: Vec<PublicKey>,
        committee: &StaticCommittee,
    ) -> Message {
        let kpair = self.keys.get(id).unwrap();
        let e = self.round_evidence((round - 1).into(), committee);
        let mut v = Vertex::new(round, e, kpair);
        v.add_edges(edges);
        let e = Envelope::signed(v, kpair);
        Message::Vertex(e.cast())
    }

    pub(crate) fn create_timeout_msgs(
        &self,
        round: u64,
        committee: &StaticCommittee,
    ) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_timeout_msg_for_node_id(id, round, committee))
            .collect()
    }

    pub(crate) fn create_timeout_msg_for_node_id(
        &self,
        id: &u64,
        round: u64,
        committee: &StaticCommittee,
    ) -> Message {
        let kpair = self.keys.get(id).unwrap();
        let evidence = self.round_evidence((round - 1).into(), committee);
        let d = Envelope::signed(TimeoutMessage::new(round, evidence, kpair), kpair);
        Message::Timeout(d.cast())
    }

    pub(crate) fn edges_for_round(
        &self,
        round: RoundNumber,
        committee: &StaticCommittee,
        ignore_leader: bool,
    ) -> Vec<PublicKey> {
        // 2f + 1 edges
        let threshold = committee.quorum_size().get() as usize;
        let leader = committee.leader(round);
        self.keys
            .values()
            .map(|kpair| *kpair.public_key())
            .filter(|pub_key| !ignore_leader || *pub_key != leader)
            .take(threshold)
            .collect()
    }

    pub(crate) fn signers_for_round(
        &self,
        round: RoundNumber,
        committee: &StaticCommittee,
        sig_count: usize,
    ) -> (BitVec, Vec<Signature>) {
        let mut signers: (BitVec, Vec<Signature>) =
            (bitvec![0; committee.size().get()], Vec::new());
        for (i, kpair) in self.keys.values().take(sig_count).enumerate() {
            let round = Envelope::signed(RoundNumber::new(*round), kpair);
            signers.0.set(i, true);
            signers.1.push(round.signature().clone());
        }
        signers
    }

    pub(crate) fn signers_for_timeout(
        &self,
        round: RoundNumber,
        committee: &StaticCommittee,
        sig_count: usize,
    ) -> (BitVec, Vec<Signature>) {
        let mut signers: (BitVec, Vec<Signature>) =
            (bitvec![0; committee.size().get()], Vec::new());
        for (i, kpair) in self.keys.values().take(sig_count).enumerate() {
            let evidence = self.round_evidence(round - 1, committee);
            let envelope = Envelope::signed(TimeoutMessage::new(*round, evidence, kpair), kpair);
            let (signed, _evidence) = envelope.into_data().into_parts();
            signers.0.set(i, true);
            signers.1.push(signed.signature().clone());
        }
        signers
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
                let e = self.round_evidence((round - 1).into(), committee);
                let v = Vertex::new(round, e.clone(), kpair);
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
        committee: &StaticCommittee,
    ) -> Message {
        let e = self.round_evidence(round - 1, committee);
        let d = Vertex::new(round, e, kpair);
        let e = Envelope::signed(d, kpair);
        Message::Vertex(e.cast())
    }

    pub(crate) fn round_evidence(
        &self,
        round: RoundNumber,
        committee: &StaticCommittee,
    ) -> Evidence {
        let signers = self.signers_for_round(round, committee, committee.size().get());
        let pp = <PublicKey as SignatureKey>::public_parameter(
            committee.stake_table(),
            U256::from(committee.quorum_size().get()),
        );
        let sig = <PublicKey as SignatureKey>::assemble(&pp, &signers.0, &signers.1);
        Evidence::Regular(Certificate::new(round, sig))
    }
}
