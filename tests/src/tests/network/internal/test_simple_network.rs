use std::sync::Arc;

use async_lock::RwLock;
use sailfish::{coordinator::CoordinatorAuditEvent, sailfish::ShutdownToken};
use timeboost_core::types::{message::Message, round_number::RoundNumber};
use tokio::{sync::oneshot, task::JoinSet, time::Duration};

use crate::{net, Group};

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis() {
    let num_nodes: usize = 5;
    let nodes = Group::new(num_nodes as u16);
    let mut net = net::Star::new();

    let mut coordinators = JoinSet::new();
    let event_logs: Vec<Arc<RwLock<Vec<CoordinatorAuditEvent>>>> = (0..num_nodes)
        .map(|_| Arc::new(RwLock::new(Vec::new())))
        .collect();
    let (shutdown_senders, mut shutdown_receivers): (
        Vec<oneshot::Sender<ShutdownToken>>,
        Vec<oneshot::Receiver<ShutdownToken>>,
    ) = (0..num_nodes).map(|_| oneshot::channel()).unzip();

    tracing::debug!("Starting the network");
    for (i, n) in nodes.fish.into_iter().enumerate() {
        let shutdown_rx = shutdown_receivers
            .pop()
            .unwrap_or_else(|| panic!("No shutdown receiver available for node {}", i));
        let ch = net.join(*n.public_key());
        let co = n.init(
            ch,
            (*nodes.staked_nodes).clone(),
            shutdown_rx,
            Some(Arc::clone(&event_logs[i])),
        );
        tracing::debug!("Started coordinator {}", i);
        coordinators.spawn(co.go());
    }

    tokio::spawn(net.run());

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get the events from each stream
    for log in event_logs.iter() {
        // Make sure we got 5 genesis vertices
        let mut gv = 0;
        for event in log.read().await.iter() {
            if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = event {
                if v.data().id().round() == RoundNumber::genesis() {
                    gv += 1;
                }
            }
        }
        assert_eq!(gv, num_nodes);
    }

    // Send a shutdown signal to all coordinators
    tracing::debug!("Shutting down the network");
    for send in shutdown_senders.into_iter() {
        let _ = send.send(ShutdownToken::new());
    }
}
