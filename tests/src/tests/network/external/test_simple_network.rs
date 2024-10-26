use std::{num::NonZeroUsize, sync::Arc};

use async_lock::RwLock;
use hotshot::traits::{
    implementations::{derive_libp2p_keypair, derive_libp2p_multiaddr},
    NetworkNodeConfigBuilder,
};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    coordinator::CoordinatorAuditEvent,
    types::{message::Message, PublicKey},
};
use tokio::{
    sync::{oneshot, Barrier},
    time::Duration,
};

use crate::Group;

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis() {
    let num_nodes: usize = 5;
    let nodes = Group::new(num_nodes as u16);

    // let mut coordinators = JoinSet::new();
    let event_logs: Vec<Arc<RwLock<Vec<CoordinatorAuditEvent>>>> = (0..num_nodes)
        .map(|_| Arc::new(RwLock::new(Vec::new())))
        .collect();
    let (shutdown_senders, mut shutdown_receivers): (
        Vec<oneshot::Sender<()>>,
        Vec<oneshot::Receiver<()>>,
    ) = (0..num_nodes).map(|_| oneshot::channel()).unzip();
    let replication_factor = NonZeroUsize::new((2 * num_nodes).div_ceil(3))
        .expect("ceil(2n/3) with n > 0 never gives 0");

    tracing::debug!("Starting the network");
    let barrier = Arc::new(Barrier::new(num_nodes));
    let mut handles = vec![];
    for (i, n) in nodes.fish.into_iter().enumerate() {
        tracing::debug!("Starting node {}", i);
        let barrier = Arc::clone(&barrier);
        let staked = Arc::clone(&nodes.staked_nodes);
        let bootstrap_nodes = Arc::clone(&nodes.bootstrap_nodes);

        let handle = tokio::spawn(async move {
            let port = 8000 + i;
            let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(&n.private_key())
                .expect("Failed to derive libp2p keypair");
            let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{port}"))
                .expect("Failed to derive libp2p multiaddr");

            let config = NetworkNodeConfigBuilder::default()
                .keypair(libp2p_keypair)
                .replication_factor(replication_factor)
                .bind_address(Some(bind_address))
                .to_connect_addrs(bootstrap_nodes.read().await.clone().into_iter().collect())
                .republication_interval(None)
                .build()
                .expect("Failed to build network node config");

            let ch = n
                .setup_libp2p(config, bootstrap_nodes, &staked)
                .await
                .expect("Failed to setup libp2p");
            barrier.wait().await;

            (ch, n)
        });
        handles.push(handle);
    }

    let networks = futures::future::join_all(handles).await;

    let mut handles = vec![];
    for (i, network) in networks.into_iter().enumerate() {
        let shutdown_rx = shutdown_receivers
            .pop()
            .expect(format!("No shutdown receiver available for node {}", i).as_str());
        let staked = Arc::clone(&nodes.staked_nodes);
        let log = Arc::clone(&event_logs[i]);
        let handle = tokio::spawn(async move {
            let (net, node) = network.expect("failed to start network");
            let co = node.init(net, (*staked).clone(), shutdown_rx, Some(Arc::clone(&log)));
            tracing::debug!("Started coordinator {}", i);

            co.go().await;
        });
        handles.push(handle);
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Get the events from each stream
    for i in 0..num_nodes {
        // Make sure we got 5 genesis vertices
        let mut gv = 0;
        for event in event_logs[i].read().await.iter() {
            match event {
                CoordinatorAuditEvent::MessageReceived(m) => match m {
                    Message::Vertex(v) => {
                        if v.data().id().round() == ViewNumber::genesis() {
                            gv += 1;
                        }
                    }
                    _ => {}
                },
                CoordinatorAuditEvent::ActionTaken(_) => {}
            }
        }
        assert_eq!(gv, num_nodes);
    }

    // Send a shutdown signal to all coordinators
    tracing::debug!("Shutting down the network");
    for send in shutdown_senders.into_iter() {
        let _ = send.send(());
    }
}
