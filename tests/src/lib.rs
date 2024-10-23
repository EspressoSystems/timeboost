/*
use async_lock::RwLock;
use hotshot::types::BLSPubKey;
use hotshot_types::{
    data::ViewNumber, traits::node_implementation::ConsensusTime, PeerConfig, ValidatorConfig,
};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use std::sync::Arc;

use sailfish::{
    consensus::{committee::StaticCommittee, Consensus, TaskContext},
    logging,
    sailfish::{generate_key_pair, Sailfish},
};

const SEED: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests;

pub struct TestableNode {
    pub nodes: Vec<Sailfish>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<BLSPubKey>>>,
}

pub fn init_nodes(num_nodes: usize) -> TestableNode {
    logging::init_logging();

    let num_nodes = num_nodes as u64;

    let mut nodes = vec![];
    let mut validator_configs = vec![];
    for i in 0..num_nodes {
        let validator_config = ValidatorConfig::generated_from_seed_indexed(SEED, i, 1, false);
        let (private_key, public_key) = generate_key_pair(SEED, i);
        let sailfish = Sailfish::new(public_key, private_key, i);
        nodes.push(sailfish);
        validator_configs.push(validator_config);
    }

    let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = nodes
        .iter()
        .map(|node| (node.peer_id, node.bind_address.clone()))
        .collect();

    let staked_nodes: Vec<PeerConfig<BLSPubKey>> = validator_configs
        .iter()
        .map(|validator_config| validator_config.public_config())
        .collect();

    let bootstrap_nodes = Arc::new(RwLock::new(bootstrap_nodes));
    let staked_nodes = Arc::new(staked_nodes);

    TestableNode {
        nodes,
        bootstrap_nodes,
        staked_nodes,
    }
}

pub fn make_consensus_nodes(num_nodes: usize) -> Vec<Consensus> {
    let mut contexts = vec![];
    let mut public_keys = vec![];
    for i in 0..num_nodes {
        let (private_key, public_key) = generate_key_pair(SEED, i as u64);
        let validator_config =
            ValidatorConfig::generated_from_seed_indexed(SEED, i as u64, 1, false);
        let context = TaskContext {
            public_key,
            private_key,
            id: i as u64,
            round: ViewNumber::genesis(),
        };
        contexts.push(context);
        public_keys.push(validator_config.public_key);
    }

    let quorum_membership = StaticCommittee::new(public_keys);

    let mut consensus_instances = vec![];
    for context in contexts.into_iter() {
        let consensus = Consensus::new(context, quorum_membership.clone());
        consensus_instances.push(consensus);
    }

    consensus_instances
}
*/
