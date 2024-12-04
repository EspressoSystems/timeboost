use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

use crate::Group;
use portpicker::pick_unused_port;
use sailfish::sailfish::Sailfish;
use timeboost_core::traits::comm::Libp2p;
use timeboost_core::types::test::message_interceptor::NetworkMessageInterceptor;
use timeboost_core::types::test::testnet::TestNet;
use timeboost_core::types::{committee::StaticCommittee, metrics::SailfishMetrics};
use timeboost_networking::network::{client::derive_libp2p_multiaddr, NetworkNodeConfigBuilder};
use tokio::{sync::watch, task::JoinSet};

use super::{TaskHandleResult, TestCondition, TestOutcome, TestableNetwork};

pub mod test_simple_network;

pub struct Libp2pNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    outcomes: HashMap<u64, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
}

impl TestableNetwork for Libp2pNetworkTest {
    type Node = Sailfish;
    type Network = Libp2p;
    type Testnet = TestNet<Self::Network>;

    fn new(
        group: Group,
        outcomes: HashMap<u64, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.fish.len()).map(|_| watch::channel(())).unzip();

        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            outcomes,
            interceptor,
        }
    }

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        let replication_factor = NonZeroUsize::new((2 * self.group.fish.len()).div_ceil(3))
            .expect("ceil(2n/3) with n > 0 never gives 0");
        let mut handles = JoinSet::new();
        for node in std::mem::take(&mut self.group.fish).into_iter() {
            let staked_nodes = Arc::clone(&self.group.staked_nodes);
            let bootstrap_nodes = Arc::clone(&self.group.bootstrap_nodes);
            let port = pick_unused_port().expect("Failed to pick an unused port");
            let libp2p_keypair = node
                .derive_libp2p_keypair()
                .expect("Failed to derive libp2p keypair");
            let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{port}"))
                .expect("Failed to derive libp2p multiaddr");
            let config = NetworkNodeConfigBuilder::default()
                .keypair(libp2p_keypair)
                .replication_factor(replication_factor)
                .bind_address(Some(bind_address))
                .to_connect_addrs(bootstrap_nodes.read().await.clone().into_iter().collect())
                .republication_interval(None)
                .build()
                .expect("Failed to build network node config");
            let committee = StaticCommittee::from(&**self.group.staked_nodes);
            handles.spawn(async move {
                let net = node
                    .setup_libp2p(config, bootstrap_nodes, &staked_nodes)
                    .await
                    .expect("Failed to start network");
                (node, Libp2p::new(net, committee))
            });
        }
        handles.join_all().await.into_iter().collect()
    }

    /// Return the result of the task handle
    /// This contains node id as well as the outcome of the test
    /// Validation logic in test will then collect this information and assert
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<TaskHandleResult> {
        let mut handles = JoinSet::new();
        let (nodes, networks) = nodes_and_networks;

        assert_eq!(
            nodes.len(),
            networks.len(),
            "Nodes and networks vectors must be the same length"
        );

        for (node, network) in nodes.into_iter().zip(networks) {
            let id: u64 = node.id().into();
            let staked_nodes = Arc::clone(&self.group.staked_nodes);
            let interceptor = self.interceptor.clone();
            let shutdown_rx = self.shutdown_rxs.remove(&(id as usize)).unwrap();
            let mut conditions = self.outcomes.remove(&id).unwrap().clone();

            handles.spawn(async move {
                let net = TestNet::new(network, id, interceptor);
                let msgs = net.messages();
                let coordinator = &mut node.init(
                    net,
                    (*staked_nodes).clone(),
                    Arc::new(SailfishMetrics::default()),
                );

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
        completed: &HashMap<u64, TestOutcome>,
    ) -> HashMap<u64, TestOutcome> {
        // Here we only send shutdown to the node ids that did not return and are still running in their respective task handles
        // Otherwise they were completed and dont need the shutdown signal
        for (id, send) in self.shutdown_txs.iter() {
            if !completed.contains_key(&(*id as u64)) {
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
            .map(|r| (r.id, r.outcome))
            .collect()
    }
}
