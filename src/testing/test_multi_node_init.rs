use async_lock::RwLock;
use hotshot::{
    traits::{implementations::derive_libp2p_keypair, NetworkNodeConfigBuilder},
    types::BLSPubKey,
};
use hotshot_types::{PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use std::{num::NonZeroUsize, sync::Arc};
use tokio::task::JoinHandle;

use crate::{
    logging,
    sailfish::{generate_key_pair, Sailfish},
};

const SEED: [u8; 32] = [0u8; 32];

pub async fn init_nodes(num_nodes: u64) {
    logging::init_logging();

    let mut nodes = vec![];
    for i in 0..num_nodes {
        let validator_config = ValidatorConfig::generated_from_seed_indexed(SEED, i, 1, false);
        let (private_key, public_key) = generate_key_pair(SEED, i);
        let sailfish = Sailfish::new(public_key, private_key, i, validator_config);
        nodes.push(sailfish);
    }

    let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = nodes
        .iter()
        .map(|node| (node.peer_id.clone(), node.bind_address.clone()))
        .collect();

    let staked_nodes: Vec<PeerConfig<BLSPubKey>> = nodes
        .iter()
        .map(|node| node.validator_config.public_config())
        .collect();

    let replication_factor = NonZeroUsize::new(((2 * num_nodes) as usize).div_ceil(3)).unwrap();

    let bootstrap_nodes = Arc::new(RwLock::new(bootstrap_nodes));
    let staked_nodes = Arc::new(staked_nodes);

    let mut handles: Vec<JoinHandle<()>> = vec![];

    for node in nodes.into_iter() {
        let bootstrap_nodes = Arc::clone(&bootstrap_nodes);
        let staked_nodes = Arc::clone(&staked_nodes);

        let handle = tokio::spawn(async move {
            let libp2p_keypair = derive_libp2p_keypair::<BLSPubKey>(&node.private_key)
                .expect("failed to derive libp2p keypair");
            let network_config = NetworkNodeConfigBuilder::default()
                .keypair(libp2p_keypair)
                .replication_factor(replication_factor)
                .bind_address(Some(node.bind_address.clone()))
                .to_connect_addrs(bootstrap_nodes.read().await.clone().into_iter().collect())
                .republication_interval(None)
                .build()
                .expect("Failed to build network node config");

            node.initialize_networking(network_config, bootstrap_nodes, (*staked_nodes).clone())
                .await;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Task failed");
    }
}

#[tokio::test]
async fn test_multi_node_init() {
    init_nodes(10).await;
}
