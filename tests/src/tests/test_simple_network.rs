use hotshot::{
    traits::{implementations::derive_libp2p_keypair, NetworkNodeConfigBuilder},
    types::BLSPubKey,
};
use std::{num::NonZeroUsize, sync::Arc};

use crate::init_nodes;

#[cfg(test)]
#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis_message() {
    use crate::make_network;

    let num_nodes = 5;
    let nodes = init_nodes(num_nodes);

    let replication_factor = NonZeroUsize::new(((2 * num_nodes) as usize).div_ceil(3)).unwrap();

    let mut coordinators = vec![];
    let mut shutdown_senders = vec![];
    for node in nodes.nodes.into_iter() {
        let bootstrap_nodes = Arc::clone(&nodes.bootstrap_nodes);
        let staked_nodes = Arc::clone(&nodes.staked_nodes);
        let node_id = node.id;
        tracing::info!("Node {} starting", node_id);

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

        let network = make_network(
            bootstrap_nodes,
            (*staked_nodes).clone(),
            node.public_key,
            node.private_key.clone(),
            network_config,
            node.id,
        )
        .await;

        let coordinator = node
            .initialize((*staked_nodes).clone(), Box::new(network))
            .await;

        let shutdown_sender = coordinator.shutdown_sender();
        shutdown_senders.push(shutdown_sender);

        coordinators.push(coordinator);
    }

    tracing::info!("{} {}", coordinators.len(), shutdown_senders.len());

    tracing::info!("Waiting for all nodes to be ready");

    let coordinator_handles = coordinators.into_iter().map(|c| tokio::spawn(c.go()));

    tracing::info!("Shutting down all nodes");
    // for handle in shutdown_senders {
    //     let _ = handle.send(()).await;
    // }

    for handle in coordinator_handles {
        handle.await.expect("Coordinator task failed");
    }
}
