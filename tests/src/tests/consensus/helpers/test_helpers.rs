use std::collections::HashMap;

use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Message, Timeout},
    round_number::RoundNumber,
    vertex::Vertex,
    PublicKey, Signature,
};

use super::{key_manager::KeyManager, node_instrument::TestNodeInstrument};
pub(crate) type MessageModifier = Box<dyn Fn(&Message, &mut TestNodeInstrument) -> Vec<Message>>;

pub(crate) fn make_consensus_nodes(
    num_nodes: u64,
) -> (HashMap<PublicKey, TestNodeInstrument>, KeyManager) {
    let manager = KeyManager::new(num_nodes);
    let nodes = manager.create_node_instruments();
    let nodes = nodes
        .into_iter()
        .map(|node_instrument| (*node_instrument.node().public_key(), node_instrument))
        .collect();
    (nodes, manager)
}

pub(crate) fn create_timeout_certificate_msg(
    env: Envelope<Timeout, Validated>,
    signers: &(BitVec, Vec<Signature>),
    committee: &StaticCommittee,
) -> Message {
    let pp = <PublicKey as SignatureKey>::public_parameter(
        committee.stake_table(),
        U256::from(committee.quorum_size().get()),
    );
    let sig = <PublicKey as SignatureKey>::assemble(&pp, &signers.0, &signers.1);
    let cert = Certificate::new(env.data().clone(), sig);
    Message::TimeoutCert(cert)
}

pub(crate) fn create_vertex(round: u64, source: PublicKey) -> Vertex {
    Vertex::new(RoundNumber::new(round), source)
}
