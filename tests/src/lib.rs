use async_lock::RwLock;
use hotshot::{
    traits::implementations::{derive_libp2p_keypair, Libp2pMetricsValue, Libp2pNetwork},
    types::{BLSPrivKey, BLSPubKey, SignatureKey},
};
use hotshot_types::{
    data::ViewNumber,
    network::{Libp2pConfig, NetworkConfig},
    traits::node_implementation::ConsensusTime,
    PeerConfig, ValidatorConfig,
};
use libp2p_identity::PeerId;
use libp2p_networking::{
    network::{
        behaviours::dht::record::{Namespace, RecordKey, RecordValue},
        NetworkNodeConfig,
    },
    reexport::Multiaddr,
};
use std::sync::Arc;

use sailfish::{
    consensus::{committee::StaticCommittee, Consensus, TaskContext},
    logging,
    sailfish::{generate_key_pair, Sailfish},
};

const SEED: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests;

pub struct TestInstance {
    pub nodes: Vec<Sailfish>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<BLSPubKey>>>,
}

pub fn init_nodes(num_nodes: usize) -> TestInstance {
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

    TestInstance {
        nodes,
        bootstrap_nodes,
        staked_nodes,
    }
}

pub fn make_consensus_nodes(num_nodes: usize) -> Vec<Consensus> {
    let mut contexts = vec![];
    let mut public_configs = vec![];
    let mut public_keys = vec![];
    for i in 0..num_nodes {
        let (private_key, public_key) = generate_key_pair(SEED, i as u64);

        let validator_config: ValidatorConfig<BLSPubKey> =
            ValidatorConfig::generated_from_seed_indexed(SEED, i as u64, 1, false);
        let context = TaskContext {
            public_key,
            private_key,
            id: i as u64,
            round_number: ViewNumber::genesis(),
        };
        contexts.push(context);
        public_configs.push(validator_config.public_config());
        public_keys.push(public_key);
    }

    let quorum_membership = StaticCommittee::new(public_keys);

    let mut consensus_instances = vec![];
    for context in contexts.into_iter() {
        let consensus = Consensus::new(context, quorum_membership.clone());
        consensus_instances.push(consensus);
    }

    consensus_instances
}

async fn make_network(
    bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    staked_nodes: Vec<PeerConfig<BLSPubKey>>,
    public_key: BLSPubKey,
    private_key: BLSPrivKey,
    config: NetworkNodeConfig<BLSPubKey>,
    id: u64,
) -> Libp2pNetwork<BLSPubKey> {
    let mut network_config = NetworkConfig::default();
    network_config.config.known_nodes_with_stake = staked_nodes.clone();
    network_config.libp2p_config = Some(Libp2pConfig {
        bootstrap_nodes: bootstrap_nodes.read().await.clone(),
    });

    // We don't have any DA nodes in Sailfish.
    network_config.config.known_da_nodes = vec![];

    let libp2p_keypair =
        derive_libp2p_keypair::<BLSPubKey>(&private_key).expect("failed to derive libp2p keypair");

    let record_value = RecordValue::new_signed(
        &RecordKey::new(Namespace::Lookup, public_key.to_bytes()),
        libp2p_keypair.public().to_peer_id().to_bytes(),
        &private_key,
    )
    .expect("failed to create record value");

    // Create the Libp2p network
    Libp2pNetwork::new(
        Libp2pMetricsValue::default(),
        config,
        public_key,
        record_value,
        bootstrap_nodes,
        usize::try_from(id).expect("id is too large"),
        false,
    )
    .await
    .expect("failed to initialize libp2p network")
}
