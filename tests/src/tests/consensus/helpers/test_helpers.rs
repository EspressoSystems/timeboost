use std::collections::HashMap;

use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Message, TimeoutMessage},
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
    env: Envelope<TimeoutMessage, Validated>,
    signers: &(BitVec, Vec<Signature>),
    committee: &StaticCommittee,
) -> Message {
    let pp = <PublicKey as SignatureKey>::public_parameter(
        committee.stake_table(),
        U256::from(committee.quorum_size().get()),
    );
    let sig = <PublicKey as SignatureKey>::assemble(&pp, &signers.0, &signers.1);
    let (timeout, _e) = env.into_data().into_parts();
    let cert = Certificate::new(timeout.into_data(), sig);
    Message::TimeoutCert(cert)
}
