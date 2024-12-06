use std::collections::HashMap;

use crate::{tests::network::TestOutcome, Group};

use super::{TaskHandleResult, TestCondition, TestableNetwork};
use sailfish::{
    coordinator::Coordinator,
    sailfish::{Sailfish, SailfishInitializerBuilder},
};
use timeboost_core::{
    traits::has_initializer::HasInitializer,
    types::{
        message::Message,
        metrics::SailfishMetrics,
        test::{
            message_interceptor::NetworkMessageInterceptor,
            net::{Conn, Star},
            testnet::{MsgQueues, TestNet},
        },
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
    star_net: Star<Message>,
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = (Coordinator<TestNet<Conn<Message>>>, MsgQueues);
    type Network = TestNet<Conn<Message>>;

    fn new(
        group: Group,
        outcomes: HashMap<usize, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.size).map(|_| watch::channel(())).unzip();
        let (network_shutdown_tx, network_shutdown_rx) = oneshot::channel();
        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            network_shutdown_tx,
            network_shutdown_rx: Some(network_shutdown_rx),
            outcomes,
            interceptor,
            star_net: Star::new(),
        }
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut coordinators = Vec::new();
        for i in 0..self.group.size {
            // Join each node to the network
            let test_net = TestNet::new(
                self.star_net.join(*self.group.keypairs[i].public_key()),
                self.interceptor.clone(),
            );
            let messages = test_net.messages();

            let initializer = SailfishInitializerBuilder::default()
                .id((i as u64).into())
                .keypair(self.group.keypairs[i].clone())
                .bind_address(self.group.addrs[i].clone())
                .network(test_net)
                .committee(self.group.committee.clone())
                .peer_id(self.group.peer_ids[i])
                .metrics(SailfishMetrics::default())
                .build()
                .unwrap();
            let n = Sailfish::initialize(initializer).await.unwrap();

            // Initialize the coordinator
            let co = n.into_coordinator();

            tracing::debug!("Started coordinator {}", i);
            let c = (co, messages);
            coordinators.push(c);
        }

        coordinators
    }

    /// Return the result of the task handle
    /// This contains node id as well as the outcome of the test
    /// Validation logic in test will then collect this information and assert
    async fn start(&mut self, nodes: Vec<Self::Node>) -> JoinSet<TaskHandleResult> {
        let mut co_handles = JoinSet::new();
        // There's always only one network for the memory network test.
        for (id, (mut coordinator, msgs)) in nodes.into_iter().enumerate() {
            let shutdown_rx = self
                .shutdown_rxs
                .remove(&id)
                .unwrap_or_else(|| panic!("No shutdown receiver available for node {}", id));
            let mut conditions = self.outcomes.get(&id).unwrap().clone();

            co_handles.spawn(async move {
                Self::run_coordinator(&mut coordinator, &mut conditions, msgs, shutdown_rx, id)
                    .await
            });
        }

        let shutdown_rx = std::mem::take(&mut self.network_shutdown_rx);

        // We don't need to own the network anymore.
        let net = std::mem::take(&mut self.star_net);
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
