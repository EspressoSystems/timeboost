use hotshot::{
    traits::{implementations::derive_libp2p_keypair, NetworkNodeConfigBuilder},
    types::BLSPubKey,
};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use std::{num::NonZeroUsize, sync::Arc};
use tokio::task::JoinHandle;

use crate::init_nodes;

#[tokio::test]
async fn test_multi_node_init() {
    let nodes = init_nodes(10);

    let replication_factor = NonZeroUsize::new(((2 * 10) as usize).div_ceil(3)).unwrap();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    for node in nodes.nodes.into_iter() {
        let bootstrap_nodes = Arc::clone(&nodes.bootstrap_nodes);
        let staked_nodes = Arc::clone(&nodes.staked_nodes);

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

            node.initialize_networking(
                network_config,
                bootstrap_nodes,
                (*staked_nodes).clone(),
                ViewNumber::new(1),
            )
            .await;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("Task failed");
    }
}
