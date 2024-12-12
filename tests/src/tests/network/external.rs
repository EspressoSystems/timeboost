use std::collections::HashMap;

use crate::Group;
use sailfish::rbc::{self, Rbc};
use sailfish::sailfish::Sailfish;
use sailfish::sailfish::SailfishInitializerBuilder;
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::metrics::SailfishMetrics;
use timeboost_core::types::test::message_interceptor::NetworkMessageInterceptor;
use timeboost_core::types::test::testnet::TestNet;
use timeboost_networking::network::client::Libp2pInitializer;
use tokio::{sync::watch, task::JoinSet};

use super::{TaskHandleResult, TestCondition, TestOutcome, TestableNetwork};

pub mod test_simple_network;

pub struct Libp2pNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    outcomes: HashMap<usize, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
}

impl TestableNetwork for Libp2pNetworkTest {
    type Node = Sailfish<Self::Network>;
    type Network = TestNet<Rbc>;

    fn new(
        group: Group,
        outcomes: HashMap<usize, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.size).map(|_| watch::channel(())).unzip();

        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            outcomes,
            interceptor,
        }
    }

    async fn init(&mut self) -> Vec<Self::Node> {
        let mut handles = JoinSet::new();
        let staked = self.group.staked_nodes.clone();
        let bootstrap_nodes = self.group.bootstrap_nodes.clone();
        let committee = self.group.committee.clone();
        for i in 0..self.group.size {
            let kpr = self.group.keypairs[i].clone();
            let addr = self.group.addrs[i].clone();
            let peer_id = self.group.peer_ids[i];
            let private_key = kpr.secret_key();

            let net_fut = Libp2pInitializer::new(
                &kpr.secret_key(),
                staked.clone(),
                bootstrap_nodes.clone().into_iter().collect(),
                addr.clone(),
            )
            .expect("failed to make libp2p initializer")
            .into_network(i, kpr.public_key(), private_key);

            let interceptor = self.interceptor.clone();
            let committee_clone = committee.clone();
            handles.spawn(async move {
                let net_inner = net_fut.await.expect("failed to make libp2p network");
                tracing::debug!(%i, "network created, waiting for ready");
                net_inner.wait_for_ready().await;
                let cfg = rbc::Config::new(kpr.clone(), committee_clone.clone());
                let net = Rbc::new(net_inner, cfg);
                tracing::debug!(%i, "created rbc");
                let test_net = TestNet::new(net, interceptor);
                tracing::debug!(%i, "created testnet");

                let initializer = SailfishInitializerBuilder::default()
                    .id((i as u64).into())
                    .keypair(kpr)
                    .bind_address(addr)
                    .network(test_net)
                    .committee(committee_clone)
                    .peer_id(peer_id)
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

        for (id, node) in nodes.into_iter().enumerate() {
            let shutdown_rx = self.shutdown_rxs.remove(&id).unwrap();
            let mut conditions = self.outcomes.get(&id).unwrap().clone();

            handles.spawn(async move {
                let msgs = node.network().messages().clone();
                let coordinator = &mut node.into_coordinator();
                Self::run_coordinator(coordinator, &mut conditions, msgs, shutdown_rx, id).await
            });
        }
        handles
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
        handles
            .join_all()
            .await
            .into_iter()
            .map(|r| (r.id(), r.outcome()))
            .collect()
    }
}
