use std::{collections::HashMap, sync::Arc};

use crate::{
    tests::network::{CoordinatorAuditEvent, TestOutcome},
    Group,
};

use super::{HandleResult, TestCondition, TestableNetwork};
use sailfish::coordinator::Coordinator;
use timeboost_core::types::{
    message::Message,
    metrics::ConsensusMetrics,
    test::{
        net::{Conn, Star},
        testnet::{MsgQueues, TestNet},
    },
};
use tokio::{
    sync::{
        oneshot::{self, Receiver, Sender},
        watch,
    },
    task::JoinSet,
};

pub mod test_simple_network;

pub struct MemoryNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    network_shutdown_tx: Sender<()>,
    network_shutdown_rx: Option<Receiver<()>>,
    outcomes: HashMap<usize, Arc<Vec<TestCondition>>>,
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = (Coordinator<TestNet<Conn<Message>>>, MsgQueues);
    type Network = Star<Message>;

    fn new(group: Group, outcomes: HashMap<usize, Arc<Vec<TestCondition>>>) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.fish.len()).map(|_| watch::channel(())).unzip();
        let (network_shutdown_tx, network_shutdown_rx) = oneshot::channel();
        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            network_shutdown_tx,
            network_shutdown_rx: Some(network_shutdown_rx),
            outcomes,
        }
    }

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut net = Star::new();
        let mut coordinators = Vec::new();
        for (i, n) in std::mem::take(&mut self.group.fish).into_iter().enumerate() {
            // Join each node to the network
            let conn = TestNet::new(net.join(*n.public_key()));
            let messages = conn.messages();

            // Initialize the coordinator
            let co = n.init(
                conn,
                (*self.group.staked_nodes).clone(),
                Arc::new(ConsensusMetrics::default()),
            );

            tracing::debug!("Started coordinator {}", i);
            let c = (co, messages);
            coordinators.push(c);
        }

        (coordinators, vec![net])
    }

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<HandleResult> {
        let mut co_handles = JoinSet::new();
        // There's always only one network for the memory network test.
        let (coordinators, mut nets) = nodes_and_networks;
        for (i, (mut co, msgs)) in coordinators.into_iter().enumerate() {
            let mut shutdown_rx = self
                .shutdown_rxs
                .remove(&i)
                .unwrap_or_else(|| panic!("No shutdown receiver available for node {}", i));
            let conditions = Arc::clone(self.outcomes.get(&i).unwrap());

            co_handles.spawn(async move {
                let mut result = HandleResult::new(i);
                let mut recv_msgs = Vec::new();
                loop {
                    tokio::select! {
                        res = co.next() => {
                            match res {
                                Ok(actions) => {
                                    recv_msgs.extend(
                                        msgs.drain_inbox().iter().map(|m| CoordinatorAuditEvent::MessageReceived(m.clone()))
                                    );
                                    if conditions.iter().all(|c| c.evaluate(&recv_msgs) == TestOutcome::Passed) {
                                        result.set_outcome(TestOutcome::Passed);
                                        break;
                                    }
                                    for a in &actions {
                                        let _ = co.execute(a.clone()).await;
                                    }
                                }
                                Err(_e) => {}
                            }
                        }
                        shutdown_result = shutdown_rx.changed() => {
                            // Unwrap the potential error with receiving the shutdown token.
                            shutdown_result.expect("The shutdown sender was dropped before the receiver could receive the token");
                            break;
                        }
                    }
                }
                result
        }
    );
        }

        let net = nets.pop().expect("memory network to be present");
        let shutdown_rx = std::mem::take(&mut self.network_shutdown_rx);
        tokio::spawn(async move { net.run(shutdown_rx.unwrap()).await });

        co_handles
    }

    async fn shutdown(
        self,
        handles: JoinSet<HandleResult>,
        completed: &HashMap<usize, HandleResult>,
    ) -> HashMap<usize, HandleResult> {
        if handles.is_empty() {
            return HashMap::new();
        }
        for (id, send) in self.shutdown_txs.iter() {
            if !completed.contains_key(id) {
                send.send(()).expect(
                    "The shutdown sender was dropped before the receiver could receive the token",
                );
            }
        }

        // Wait for all the coordinators to shutdown
        let res: HashMap<usize, HandleResult> = handles
            .join_all()
            .await
            .into_iter()
            .map(|r| (r.id(), r)) // Use item.id() as key
            .collect();

        // Now shutdown the network
        let _ = self.network_shutdown_tx.send(());
        res
    }
}
