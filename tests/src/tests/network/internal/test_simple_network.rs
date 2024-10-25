use std::sync::Arc;

use async_lock::RwLock;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{coordinator::CoordinatorAuditEvent, types::message::Message};
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    sync::oneshot,
    task::JoinSet,
    time::{timeout, Duration},
};

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
    let (mut shutdown_senders, mut shutdown_receivers): (
        Vec<oneshot::Sender<()>>,
        Vec<oneshot::Receiver<()>>,
    ) = (0..num_nodes).map(|_| oneshot::channel()).unzip();

    tracing::debug!("Starting the network");
    for (i, n) in nodes.fish.into_iter().enumerate() {
        let shutdown_rx = shutdown_receivers
            .pop()
            .expect(format!("No shutdown receiver available for node {}", i).as_str());
        let ch = net.join(n.public_key().clone());
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

    tokio::time::sleep(Duration::from_millis(20)).await;

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
