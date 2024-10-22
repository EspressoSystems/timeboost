use hotshot::{
    traits::{implementations::derive_libp2p_keypair, NetworkNodeConfigBuilder},
    types::BLSPubKey,
};
use sailfish::types::message::SailfishEvent;
use sailfish::utils::network::broadcast_event;
use std::{collections::HashMap, time::Duration};
use std::{num::NonZeroUsize, sync::Arc};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::init_nodes;

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis_message() {
    let num_nodes: usize = 5;
    let nodes = init_nodes(num_nodes);

    let replication_factor = NonZeroUsize::new(((2 * num_nodes) as usize).div_ceil(3)).unwrap();

    let mut handles: Vec<JoinHandle<()>> = vec![];

    // Get the event streams of each node
    let event_receivers = nodes
        .nodes
        .iter()
        .map(|node| (node.id, node.internal_event_stream.clone()))
        .collect::<Vec<_>>();

    let external_streams = nodes
        .nodes
        .iter()
        .map(|node| node.external_event_stream.clone())
        .collect::<Vec<_>>();

    // This barrier ensures that all nodes are ready to receive events before we start the event loop.
    let barrier = Arc::new(tokio::sync::Barrier::new(num_nodes));
    for node in nodes.nodes.into_iter() {
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

            node.initialize_networking(network_config, bootstrap_nodes, (*staked_nodes).clone())
                .await;

            barrier.wait().await;
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
            let result = timeout(Duration::from_millis(250), async {
                loop {
                    match event_receiver.1.recv().await {
                        Ok(event) => {
                            tracing::debug!("Node {} received event: {}", id, event);
                            events.push(event);
                            tokio::task::yield_now().await;
                        }
                        Err(_) => break,
                    }
                }
            })
            .await;
            match result {
                Ok(_) => tracing::debug!("Node {} finished receiving events", id),
                Err(_) => tracing::debug!("Node {} timed out after 250ms", id),
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

    // TODO: This is not great since we cannot assert that we've received the correct data
    // from each node. We should get a better suite together at some point.
    let expectations: Vec<(fn(&SailfishEvent) -> bool, usize)> = vec![
        (
            |e| matches!(e, SailfishEvent::VertexCertificateRecv(_)),
            num_nodes,
        ),
        (|e| matches!(e, SailfishEvent::VertexVoteRecv(_)), num_nodes),
        (|e| matches!(e, SailfishEvent::VertexRecv(_, _)), num_nodes),
    ];

    for (id, events) in received_events.into_iter() {
        tracing::debug!(
            "Node {} received events: {:?}",
            id,
            events.iter().map(|e| format!("{e}")).collect::<Vec<_>>()
        );

        for (event_matcher, expected_count) in &expectations {
            let actual_count = events.iter().filter(|e| event_matcher(e)).count();
            assert!(
                actual_count >= *expected_count,
                "Node {} received {} {:?} events, expected {}",
                id,
                actual_count,
                events
                    .iter()
                    .find(|e| event_matcher(e))
                    .map(|e| format!("{}", e))
                    .unwrap_or_default(),
                expected_count
            );
        }
    }

    // Send the shutdown event to all nodes
    for event_stream in external_streams {
        broadcast_event(SailfishEvent::Shutdown, &event_stream.0).await;
    }

    for (_, event_stream) in event_receivers {
        broadcast_event(SailfishEvent::Shutdown, &event_stream.0).await;
    }
}
