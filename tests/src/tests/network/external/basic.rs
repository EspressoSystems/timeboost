use std::collections::HashMap;

use crate::tests::network::{TaskHandleResult, TestCondition, TestableNetwork};
use crate::Group;
use sailfish::metrics::SailfishMetrics;
use sailfish::rbc::{self, Rbc};
use sailfish::sailfish::Sailfish;
use sailfish::sailfish::SailfishInitializerBuilder;
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::test::message_interceptor::NetworkMessageInterceptor;
use timeboost_core::types::test::testnet::TestNet;
use timeboost_networking::{Network, NetworkMetrics};
use tokio::task::JoinSet;

pub struct BasicNetworkTest {
    group: Group,
    outcomes: HashMap<u64, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
}

impl TestableNetwork for BasicNetworkTest {
    type Node = Sailfish<Self::Network>;
    type Network = TestNet<Rbc>;

    fn new(
        group: Group,
        outcomes: HashMap<u64, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        Self {
            group,
            outcomes,
            interceptor,
        }
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        let mut handles = JoinSet::new();
        let committee = self.group.committee.clone();
        for i in 0..self.group.size {
            let kpr = self.group.keypairs[i].clone();
            let addr = *self
                .group
                .peers
                .get(&kpr.public_key())
                .expect("own public key to be present");
            let net = Network::create(
                addr,
                kpr.clone(),
                self.group.peers.clone(),
                NetworkMetrics::default(),
            )
            .await
            .expect("failed to make network");
            let interceptor = self.interceptor.clone();
            let committee_clone = committee.clone();
            handles.spawn(async move {
                let cfg = rbc::Config::new(kpr.clone(), committee_clone.clone());
                let net = Rbc::new(net, cfg);
                tracing::debug!(%i, "created rbc");
                let test_net = TestNet::new(net, i as u64, interceptor);
                tracing::debug!(%i, "created testnet");

                let initializer = SailfishInitializerBuilder::default()
                    .id((i as u64).into())
                    .keypair(kpr)
                    .bind_address(addr)
                    .network(test_net)
                    .committee(committee_clone)
                    .metrics(SailfishMetrics::default())
                    .build()
                    .unwrap();

                Sailfish::initialize(initializer).await.unwrap()
            });
        }
        handles.join_all().await.into_iter().collect()
    }

    /// Return the result of the task handle
    /// This contains node id as well as the outcome of the test
    /// Validation logic in test will then collect this information and assert
    async fn start(&mut self, nodes: Vec<Self::Node>) -> JoinSet<TaskHandleResult> {
        let mut handles = JoinSet::new();

        for node in nodes.into_iter() {
            let id: u64 = node.id().into();
            let mut conditions = self.outcomes.remove(&id).unwrap();

            handles.spawn(async move {
                let msgs = node.network().messages().clone();
                let coordinator = &mut node.into_coordinator();
                Self::run_coordinator(coordinator, &mut conditions, msgs, id).await
            });
        }
        handles
    }
}
