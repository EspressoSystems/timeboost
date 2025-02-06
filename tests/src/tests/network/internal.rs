use std::collections::HashMap;

use crate::Group;

use super::{TaskHandleResult, TestCondition, TestableNetwork};
use sailfish::{
    coordinator::Coordinator,
    metrics::SailfishMetrics,
    sailfish::{Sailfish, SailfishInitializerBuilder},
};
use timeboost_core::{
    traits::has_initializer::HasInitializer,
    types::{
        message::Message,
        test::{
            message_interceptor::NetworkMessageInterceptor,
            net::{Conn, Star},
            testnet::{MsgQueues, TestNet},
        },
    },
};
use tokio::task::{JoinHandle, JoinSet};

pub mod test_simple_network;

pub struct MemoryNetworkTest {
    group: Group,
    outcomes: HashMap<u64, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
    star_net: Star<Message>,
    jh: JoinHandle<()>,
}

impl Drop for MemoryNetworkTest {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = (Coordinator<TestNet<Conn<Message>>>, MsgQueues);
    type Network = TestNet<Conn<Message>>;

    fn new(
        group: Group,
        outcomes: HashMap<u64, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        Self {
            group,
            outcomes,
            interceptor,
            star_net: Star::new(),
            jh: tokio::spawn(async {}),
        }
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut coordinators = Vec::new();
        for i in 0..self.group.size {
            // Join each node to the network
            let test_net = TestNet::new(
                self.star_net.join(self.group.keypairs[i].public_key()),
                i as u64,
                self.interceptor.clone(),
            );
            let messages = test_net.messages();
            let kpr = self.group.keypairs[i].clone();
            let addr = *self
                .group
                .peers
                .get(&kpr.public_key())
                .expect("own public key to be present");
            let initializer = SailfishInitializerBuilder::default()
                .id((i as u64).into())
                .keypair(kpr)
                .bind_address(addr)
                .network(test_net)
                .committee(self.group.committee.clone())
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
        for (mut coordinator, msgs) in nodes.into_iter() {
            let id: u64 = coordinator.id().into();
            let mut conditions = self.outcomes.remove(&id).unwrap();

            co_handles.spawn(async move {
                Self::run_coordinator(&mut coordinator, &mut conditions, msgs, id).await
            });
        }

        // We don't need to own the network anymore.
        let net = std::mem::take(&mut self.star_net);
        self.jh = tokio::spawn(async move { net.run().await });

        co_handles
    }
}
