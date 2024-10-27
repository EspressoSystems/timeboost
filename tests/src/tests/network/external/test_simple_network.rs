use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

use async_lock::RwLock;
use hotshot::traits::{
    implementations::{derive_libp2p_keypair, derive_libp2p_multiaddr},
    NetworkNodeConfigBuilder,
};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    coordinator::CoordinatorAuditEvent,
    types::{envelope::Envelope, message::Message, vertex::Vertex, PublicKey},
};
use tokio::{
    sync::{oneshot, Barrier},
    task::JoinSet,
    time::{timeout, Duration},
};

use crate::{
    tests::network::{external::Libp2pTest, TestCondition, TestOutcome},
    Group,
};

#[tokio::test]
async fn test_simple_network_genesis2() {
    let num_nodes = 5;
    let group = Group::new(num_nodes as u16);
    // Each node should see the genesis vertex from every other node.
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|n| {
                    let node_public_key = n.public_key().clone();
                    TestCondition::new(
                        format!("Genesis Vertex from {}", node_id),
                        Box::new(move |e| {
                            if let CoordinatorAuditEvent::MessageReceived(m) = e {
                                if let Message::Vertex(v) = m {
                                    if v.data().id().round() == ViewNumber::genesis()
                                        && node_public_key == *v.data().source()
                                    {
                                        return TestOutcome::Passed;
                                    }
                                }
                            }
                            TestOutcome::Waiting
                        }),
                    )
                })
                .collect();
            (node_id, conditions)
        })
        .collect();

    let mut test = Libp2pTest::new(group, node_outcomes);
    let networks = test.init().await;
    let test_handles = test.start(networks).await;

    let mut st_interim = HashMap::new();
    let final_statuses = match timeout(Duration::from_millis(250), async {
        loop {
            let statuses = test.evaluate().await;
            st_interim = statuses.clone();
            if !statuses.values().all(|s| *s == TestOutcome::Passed) {
                tokio::time::sleep(Duration::from_millis(2)).await;
                tokio::task::yield_now().await;
            } else {
                return statuses;
            }
        }
    })
    .await
    {
        Ok(statuses) => statuses,
        Err(_) => {
            for (node_id, status) in st_interim.iter() {
                if *status != TestOutcome::Passed {
                    println!("Node {} had missing status: {}", node_id, status);
                }
            }

            panic!("Test timed out after 250ms")
        }
    };

    test.shutdown(test_handles).await;

    // Now verify all statuses are Passed
    assert!(
        final_statuses.values().all(|s| *s == TestOutcome::Passed),
        "Not all nodes passed. Final statuses: {:?}",
        final_statuses
    );
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis() {
    let num_nodes: usize = 5;
    let nodes = Group::new(num_nodes as u16);

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
    let mut handles = JoinSet::new();
    for (i, n) in nodes.fish.into_iter().enumerate() {
        tracing::debug!("Starting node {}", i);
        let barrier = Arc::clone(&barrier);
        let staked = Arc::clone(&nodes.staked_nodes);
        let bootstrap_nodes = Arc::clone(&nodes.bootstrap_nodes);

        handles.spawn(async move {
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
    }

    let networks = handles.join_all().await;

    let mut handles = JoinSet::new();
    for (i, network) in networks.into_iter().enumerate() {
        let shutdown_rx = shutdown_receivers
            .pop()
            .expect(format!("No shutdown receiver available for node {}", i).as_str());
        let staked = Arc::clone(&nodes.staked_nodes);
        let log = Arc::clone(&event_logs[i]);
        handles.spawn(async move {
            let (net, node) = network;
            let co = node.init(net, (*staked).clone(), shutdown_rx, Some(Arc::clone(&log)));
            tracing::debug!("Started coordinator {}", i);

            co.go().await;
        });
    }

    let mut genesis_vertices_seen: HashMap<usize, usize> =
        HashMap::from_iter((0..num_nodes).map(|i| (i, 0)));

    // Get the events from each stream
    for i in 0..num_nodes {
        // Make sure we got 5 genesis vertices
        // let mut gv = 0;
        for event in event_logs[i].read().await.iter() {
            match event {
                CoordinatorAuditEvent::MessageReceived(m) => match m {
                    Message::Vertex(v) => {
                        if v.data().id().round() == ViewNumber::genesis() {
                            genesis_vertices_seen
                                .entry(i)
                                .and_modify(|c| *c += 1)
                                .or_insert(1);
                        }
                    }
                    _ => {}
                },
                CoordinatorAuditEvent::ActionTaken(_) => {}
            }
        }
        // assert_eq!(gv, num_nodes);
    }

    // Send a shutdown signal to all coordinators
    tracing::debug!("Shutting down the network");
    for send in shutdown_senders.into_iter() {
        let _ = send.send(());
    }

    handles.join_all().await;
}
