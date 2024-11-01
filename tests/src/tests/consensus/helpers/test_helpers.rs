use std::collections::HashMap;

use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use sailfish::consensus::Consensus;
use sailfish::sailfish::generate_key_pair;
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Message, Timeout},
    round_number::RoundNumber,
    vertex::Vertex,
    NodeId, PrivateKey, PublicKey, Signature,
};

use super::node_instrument::TestNodeInstrument;
pub(crate) type MessageModifier = Box<dyn Fn(&Message, &mut TestNodeInstrument) -> Vec<Message>>;

const SEED: [u8; 32] = [0u8; 32];

pub(crate) fn create_keys(num_nodes: u64) -> Vec<(PrivateKey, PublicKey)> {
    (0..num_nodes)
        .map(|i| generate_key_pair(SEED, i))
        .collect::<Vec<_>>()
}

pub(crate) fn create_node_instruments(
    keys: Vec<(PrivateKey, PublicKey)>,
) -> Vec<TestNodeInstrument> {
    let committee = StaticCommittee::new(keys.iter().map(|(_, k)| k).cloned().collect());
    keys.into_iter()
        .enumerate()
        .map(|(id, (private_key, pub_key))| {
            let node_id = NodeId::from(id as u64);
            TestNodeInstrument::new(Consensus::new(
                node_id,
                pub_key,
                private_key,
                committee.clone(),
            ))
        })
        .collect()
}

pub(crate) fn create_nodes(num_nodes: u64) -> HashMap<PublicKey, TestNodeInstrument> {
    let keys = create_keys(num_nodes);
    let nodes = create_node_instruments(keys);
    nodes
        .into_iter()
        .map(|node_instrument| (*node_instrument.node.public_key(), node_instrument))
        .collect()
}

pub(crate) fn create_timeout_vote(
    round: RoundNumber,
    pub_key: PublicKey,
    private_key: &PrivateKey,
) -> Envelope<Timeout, Validated> {
    let data = Timeout::new(round);
    Envelope::signed(data, private_key, pub_key)
}

pub(crate) fn create_timeout_vote_msg(
    timeout_round: RoundNumber,
    pub_key: PublicKey,
    private_key: &PrivateKey,
) -> Message {
    let e = create_timeout_vote(timeout_round, pub_key, private_key);
    Message::Timeout(e.cast())
}

pub(crate) fn create_vertex_proposal_msg(
    round: RoundNumber,
    pub_key: PublicKey,
    private_key: &PrivateKey,
) -> Message {
    let data = Vertex::new(round, pub_key);
    let e = Envelope::signed(data, private_key, pub_key);
    Message::Vertex(e.cast())
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
