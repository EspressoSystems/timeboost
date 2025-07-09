pub mod test_simple_network;

use std::collections::HashMap;

use cliquenet::{Network, NetworkMetrics, Overlay};
use multisig::PublicKey;
use sailfish::Coordinator;
use sailfish::rbc::{Rbc, RbcConfig};
use tokio::task::JoinSet;

use crate::Group;
use crate::prelude::*;
use crate::tests::network::message_interceptor::NetworkMessageInterceptor;
use crate::tests::network::testnet::{MsgQueues, TestNet};
use crate::tests::network::{TaskHandleResult, TestCondition, TestableNetwork};

pub struct BasicNetworkTest {
    group: Group,
    outcomes: HashMap<PublicKey, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor<SailfishBlock>,
}

impl TestableNetwork for BasicNetworkTest {
    type Node = (
        Coordinator<SailfishBlock, Self::Network>,
        MsgQueues<SailfishBlock>,
    );
    type Network = TestNet<SailfishBlock, Rbc<SailfishBlock>>;

    fn new(
        group: Group,
        outcomes: HashMap<PublicKey, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor<SailfishBlock>,
    ) -> Self {
        Self {
            group,
            outcomes,
            interceptor,
        }
    }

    fn public_key(&self, n: &Self::Node) -> PublicKey {
        n.0.public_key()
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        let committee = self.group.committee.clone();
        let mut nodes = Vec::new();
        for i in 0..self.group.size {
            let kpr = self.group.sign_keypairs[i].clone();
            let xpr = self.group.dh_keypairs[i].clone();
            let addr = *self
                .group
                .peers
                .iter()
                .find_map(|(p, _, a)| (*p == kpr.public_key()).then_some(a))
                .expect("own public key to be present");
            let net = Network::create(
                "test",
                addr,
                kpr.public_key(),
                xpr.clone(),
                self.group.peers.clone(),
                NetworkMetrics::default(),
            )
            .await
            .expect("failed to make network");
            let cfg = RbcConfig::new(kpr.clone(), committee.id(), committee.clone()).recover(false);
            let net = Rbc::new(committee.size().get() * 5, Overlay::new(net), cfg);
            tracing::debug!(%i, "created rbc");
            let test_net = TestNet::new(net, i as u64, self.interceptor.clone());
            let messages = test_net.messages();
            tracing::debug!(%i, "created testnet");
            let consensus = Consensus::new(kpr, committee.clone(), EmptyBlocks);
            let coord = Coordinator::new(test_net, consensus, false);
            nodes.push((coord, messages))
        }
        nodes
    }

    /// Return the result of the task handle
    /// This contains node id as well as the outcome of the test
    /// Validation logic in test will then collect this information and assert
    async fn start(&mut self, nodes: Vec<Self::Node>) -> JoinSet<TaskHandleResult> {
        let mut handles = JoinSet::new();

        for mut node in nodes.into_iter() {
            let mut conditions = self.outcomes.remove(&node.0.public_key()).unwrap();

            handles.spawn(async move {
                Self::run_coordinator(&mut node.0, &mut conditions, node.1.clone()).await
            });
        }
        handles
    }
}
