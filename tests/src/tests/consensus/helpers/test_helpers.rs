use std::collections::HashMap;

use multisig::{Committee, Envelope, PublicKey, Validated, VoteAccumulator};
use timeboost_core::types::message::{Message, Timeout};

use super::{key_manager::KeyManager, node_instrument::TestNodeInstrument};
pub(crate) type MessageModifier = Box<dyn Fn(&Message, &mut TestNodeInstrument) -> Vec<Message>>;

pub(crate) fn make_consensus_nodes(
    num_nodes: u64,
) -> (HashMap<PublicKey, TestNodeInstrument>, KeyManager) {
    let manager = KeyManager::new(num_nodes);
    let nodes = manager.create_node_instruments();
    let nodes = nodes
        .into_iter()
        .map(|node_instrument| (node_instrument.node().public_key(), node_instrument))
        .collect();
    (nodes, manager)
}

pub(crate) fn create_timeout_certificate_msg(
    env: Vec<Envelope<Timeout, Validated>>,
    committee: &Committee,
) -> Message {
    let mut va = VoteAccumulator::new(committee.clone());
    for e in env {
        va.add(e).unwrap();
    }
    Message::TimeoutCert(va.certificate().unwrap().clone())
}
