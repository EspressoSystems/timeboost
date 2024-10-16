use hotshot::{
    traits::{implementations::derive_libp2p_keypair, NetworkNodeConfigBuilder},
    types::BLSPubKey,
};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::types::message::SailfishEvent;
use sailfish::utils::network::broadcast_event;
use std::{collections::HashMap, time::Duration};
use std::{num::NonZeroUsize, sync::Arc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::init_nodes;

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_startup_message() {
    let num_nodes: usize = 5;
    let nodes = init_nodes(num_nodes);

    let replication_factor = NonZeroUsize::new(((2 * num_nodes) as usize).div_ceil(3)).unwrap();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    // Get the event streams of each node
    let event_receivers = nodes
        .nodes
        .iter()
        .map(|node| (node.state.id, node.internal_event_stream.clone()))
        .collect::<Vec<_>>();

    // This barrier ensures that all nodes are ready to receive events before we start the event loop.
    let barrier = Arc::new(tokio::sync::Barrier::new(num_nodes));
    for mut node in nodes.nodes.into_iter() {
        let bootstrap_nodes = Arc::clone(&nodes.bootstrap_nodes);
        let staked_nodes = Arc::clone(&nodes.staked_nodes);
        let barrier = Arc::clone(&barrier);

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

            barrier.wait().await;

            node.run().await;
        });

        handles.push(handle);
    }

    // Wait for all networks to be ready.
    futures::future::join_all(handles.into_iter()).await;

    // Receive events from all nodes
    let mut receive_handles = Vec::new();
    for (id, mut event_receiver) in event_receivers.iter().cloned() {
        let handle = tokio::spawn(async move {
            tracing::info!("Receiving events for node {}", id);
            let mut events = Vec::<SailfishEvent>::new();
            loop {
                match timeout(Duration::from_millis(250), event_receiver.1.recv()).await {
                    Ok(Ok(event)) => {
                        tracing::info!("Node {} received event: {}", id, event);
                        events.push(event);
                    }
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            (id, events)
        });
        receive_handles.push(handle);
    }

    // Resolve the tokio join handles
    let mut received_events = HashMap::new();
    for handle in receive_handles {
        let (id, events) = handle.await.expect("Task failed");
        received_events.insert(id, events);
    }

    // Assert that each node received a dummy event from every other node, so for 5 nodes, we should
    // have gotten DummyRecv(0), DummyRecv(1), ..., DummyRecv(4)
    let expected_events = (0..num_nodes as u64)
        .map(|i| SailfishEvent::DummyRecv(i))
        .collect::<Vec<_>>();

    for (id, mut events) in received_events.into_iter() {
        assert_eq!(
            events.len(),
            num_nodes,
            "Node {} did not receive all dummy events",
            id
        );
        // Sort the events by sender ID
        events.sort_by_key(|event| match event {
            SailfishEvent::DummyRecv(sender_id) => *sender_id,
            other => panic!("Unexpected event type received; event = {}", other),
        });

        // Now, unwrap the Arc to compare the events
        assert_eq!(
            events.into_iter().map(|e| e.clone()).collect::<Vec<_>>(),
            expected_events
        );
    }

    // Send the shutdown event to all nodes
    for (_, event_stream) in event_receivers {
        broadcast_event(SailfishEvent::Shutdown, &event_stream.0).await;
    }
}
