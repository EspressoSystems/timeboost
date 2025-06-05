use std::collections::HashMap;

use multisig::PublicKey;
use net::{Conn, Star};
use sailfish::Coordinator;
use sailfish::types::PLACEHOLDER;
use tokio::task::{JoinHandle, JoinSet};

use super::message_interceptor::NetworkMessageInterceptor;
use super::testnet::{MsgQueues, TestNet};
use super::{TaskHandleResult, TestCondition, TestableNetwork};
use crate::Group;
use crate::prelude::*;

mod net;
pub mod test_simple_network;

pub struct MemoryNetworkTest {
    group: Group,
    outcomes: HashMap<PublicKey, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor<SailfishBlock>,
    star_net: Star<Message>,
    jh: JoinHandle<()>,
}

impl Drop for MemoryNetworkTest {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = (
        Coordinator<SailfishBlock, TestNet<SailfishBlock, Conn<Message>>>,
        MsgQueues<SailfishBlock>,
    );
    type Network = TestNet<SailfishBlock, Conn<Message>>;

    fn new(
        group: Group,
        outcomes: HashMap<PublicKey, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor<SailfishBlock>,
    ) -> Self {
        Self {
            group,
            outcomes,
            interceptor,
            star_net: Star::new(),
            jh: tokio::spawn(async {}),
        }
    }

    fn public_key(&self, n: &Self::Node) -> PublicKey {
        n.0.public_key()
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        let mut coordinators = Vec::new();
        for i in 0..self.group.size {
            // Join each node to the network
            let test_net = TestNet::new(
                self.star_net.join(self.group.sign_keypairs[i].public_key()),
                i as u64,
                self.interceptor.clone(),
            );
            let messages = test_net.messages();
            let kpr = self.group.sign_keypairs[i].clone();

            let comm = self.group.committee.clone();
            let cons = Consensus::new(kpr, comm, EmptyBlocks);
            let coor = Coordinator::new(test_net, cons);

            coordinators.push((coor, messages))
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
            let mut conditions = self.outcomes.remove(&coordinator.public_key()).unwrap();

            co_handles.spawn(async move {
                Self::run_coordinator(&mut coordinator, &mut conditions, msgs).await
            });
        }

        // We don't need to own the network anymore.
        let net = std::mem::take(&mut self.star_net);
        self.jh = tokio::spawn(async move { net.run().await });

        co_handles
    }
}
