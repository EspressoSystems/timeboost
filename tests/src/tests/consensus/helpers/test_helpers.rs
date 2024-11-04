use std::collections::VecDeque;

use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use sailfish::consensus::Consensus;
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Message, Timeout},
    round_number::RoundNumber,
    vertex::Vertex,
    Keypair, NodeId, PublicKey, Signature,
};
pub(crate) type MessageModifier =
    Box<dyn Fn(&Message, &StaticCommittee, &mut VecDeque<Message>) -> Vec<Message>>;

pub(crate) fn make_consensus_nodes(num_nodes: u64) -> Vec<Consensus> {
    let keys = (0..num_nodes).map(Keypair::zero).collect::<Vec<_>>();
    let committee = StaticCommittee::new(keys.iter().map(|k| *k.public_key()).collect());
    keys.into_iter()
        .enumerate()
        .map(|(i, kpair)| {
            let node_id = NodeId::from(i as u64);
            Consensus::new(node_id, kpair, committee.clone())
        })
        .collect()
}

pub(crate) fn create_vertex_proposal_msg(round: RoundNumber, kpair: &Keypair) -> Message {
    let d = Vertex::new(round, *kpair.public_key());
    let e = Envelope::signed(d, kpair);
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
