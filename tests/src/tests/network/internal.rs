use std::{collections::HashMap, sync::Arc};

use crate::{
    tests::network::{CoordinatorAuditEvent, TestOutcome},
    Group,
};

use super::{TaskHandleResult, TestCondition, TestableNetwork};
use sailfish::coordinator::Coordinator;
use timeboost_core::types::{
    committee::StaticCommittee,
    message::Message,
    metrics::ConsensusMetrics,
    test::{
        message_interceptor::NetworkMessageInterceptor,
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
    outcomes: HashMap<usize, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = (Coordinator<TestNet<Conn<Message>>>, MsgQueues);
    type Network = Star<Message>;

    fn new(
        group: Group,
        outcomes: HashMap<usize, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
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
            interceptor,
        }
    }

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut net = Star::new();
        let mut coordinators = Vec::new();
        for (i, n) in std::mem::take(&mut self.group.fish).into_iter().enumerate() {
            // Join each node to the network
            let committee = StaticCommittee::from(&*(*self.group.staked_nodes).clone());
            let test_net = TestNet::new(
                net.join(*n.public_key()),
                self.interceptor.clone(),
                committee,
            );
            let messages = test_net.messages();

            // Initialize the coordinator
            let co = n.init(
                test_net,
                (*self.group.staked_nodes).clone(),
                Arc::new(ConsensusMetrics::default()),
            );

            tracing::debug!("Started coordinator {}", i);
            let c = (co, messages);
            coordinators.push(c);
        }

        (coordinators, vec![net])
    }

    /// Return the result of the task handle
    /// This contains node id as well as the outcome of the test
    /// Validation logic in test will then collect this information and assert
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<TaskHandleResult> {
        let mut co_handles = JoinSet::new();
        // There's always only one network for the memory network test.
        let (coordinators, mut nets) = nodes_and_networks;
        for (i, (mut co, msgs)) in coordinators.into_iter().enumerate() {
            let mut shutdown_rx = self
                .shutdown_rxs
                .remove(&i)
                .unwrap_or_else(|| panic!("No shutdown receiver available for node {}", i));
            let mut conditions = self.outcomes.get(&i).unwrap().clone();

            co_handles.spawn(async move {
                match co.start().await {
                    Ok(actions) => {
                        for a in actions {
                            let _ = co.execute(a).await;
                        }
                    }
                    Err(e) => {
                        panic!("Failed to start coordinator: {}", e);
                    }
                }
                loop {
                    let mut events = Vec::new();
                    tokio::select! {
                        res = co.next() => match res {
                            Ok(actions) => {
                                events.extend(
                                    msgs.drain_inbox().iter().map(|m| CoordinatorAuditEvent::MessageReceived(m.clone()))
                                );
                                for a in actions {
                                    events.push(CoordinatorAuditEvent::ActionTaken(a.clone()));
                                    let _ = co.execute(a).await;
                                }
                                // Evaluate if we have seen the specified conditions of the test
                                if Self::evaluate(&mut conditions, &events) {
                                    // We are done with this nodes test, we can break our loop and pop off `JoinSet` handles
                                    // Allow us some time to send out any messages
                                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    co.shutdown().await.expect("Network to be shutdown");
                                    break TaskHandleResult::new(i ,TestOutcome::Passed);
                                }
                            }
                            Err(_e) => {}
                        },
                        shutdown_result = shutdown_rx.changed() => {
                            // Unwrap the potential error with receiving the shutdown token.
                            co.shutdown().await.expect("Network to be shutdown");
                            shutdown_result.expect("The shutdown sender was dropped before the receiver could receive the token");
                            break TaskHandleResult::new(i, TestOutcome::Failed);
                        }
                    }
                }
            });
        }

        let net = nets.pop().expect("memory network to be present");
        let shutdown_rx = std::mem::take(&mut self.network_shutdown_rx);
        tokio::spawn(async move { net.run(shutdown_rx.unwrap()).await });

        co_handles
    }

    /// Shutdown any spawned tasks that are running
    /// This will then be evaluated as failures in the test validation logic
    async fn shutdown(
        self,
        handles: JoinSet<TaskHandleResult>,
        completed: &HashMap<usize, TestOutcome>,
    ) -> HashMap<usize, TestOutcome> {
        // Here we only send shutdown to the node ids that did not return and are still running in their respective task handles
        // Otherwise they were completed and dont need the shutdown signal
        for (id, send) in self.shutdown_txs.iter() {
            if !completed.contains_key(id) {
                send.send(()).expect(
                    "The shutdown sender was dropped before the receiver could receive the token",
                );
            }
        }

        // Wait for all the coordinators to shutdown
        let res: HashMap<usize, TestOutcome> = handles
            .join_all()
            .await
            .into_iter()
            .map(|r| (r.id(), r.outcome()))
            .collect();

        // Now shutdown the network
        let _ = self.network_shutdown_tx.send(());
        res
    }
}
