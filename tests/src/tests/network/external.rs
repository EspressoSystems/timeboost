use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

use portpicker::pick_unused_port;
use sailfish::sailfish::Sailfish;
use timeboost_core::types::{metrics::ConsensusMetrics, test::testnet::TestNet, PublicKey};
use timeboost_networking::network::{
    client::{derive_libp2p_multiaddr, Libp2pNetwork},
    NetworkNodeConfigBuilder,
};
use tokio::{sync::watch, task::JoinSet};

use crate::{tests::network::CoordinatorAuditEvent, Group};

use super::{HandleResult, TestCondition, TestOutcome, TestableNetwork};

pub mod test_simple_network;

pub struct Libp2pNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    outcomes: HashMap<usize, Arc<Vec<TestCondition>>>,
}

impl TestableNetwork for Libp2pNetworkTest {
    type Node = Sailfish;
    type Network = Libp2pNetwork<PublicKey>;

    fn new(group: Group, outcomes: HashMap<usize, Arc<Vec<TestCondition>>>) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.fish.len()).map(|_| watch::channel(())).unzip();

        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            outcomes,
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
            handles.spawn(async move {
                let net = node
                    .setup_libp2p(config, bootstrap_nodes, &staked_nodes)
                    .await
                    .expect("Failed to start network");
                (node, net)
            });
        }
        handles.join_all().await.into_iter().collect()
    }

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<HandleResult> {
        let mut handles = JoinSet::new();
        let (nodes, networks) = nodes_and_networks;

        assert_eq!(
            nodes.len(),
            networks.len(),
            "Nodes and networks vectors must be the same length"
        );

        for (i, (node, network)) in nodes.into_iter().zip(networks).enumerate() {
            let staked_nodes = Arc::clone(&self.group.staked_nodes);
            let conditions = Arc::clone(self.outcomes.get(&i).unwrap());
            let mut shutdown_rx = self.shutdown_rxs.remove(&i).unwrap();

            handles.spawn(async move {
                let net = TestNet::new(network);
                let msgs = net.messages();
                let mut coordinator = node.init(
                    net,
                    (*staked_nodes).clone(),
                    Arc::new(ConsensusMetrics::default()),
                );

                let mut result = HandleResult::new(i);
                let mut events = Vec::new();

                match coordinator.start().await {
                    Ok(actions) => {
                        for a in actions {
                            let _ = coordinator.execute(a).await;
                        }
                    }
                    Err(e) => {
                        panic!("Failed to start coordinator: {}", e);
                    }
                }
                loop {
                    tokio::select! {
                        res = coordinator.next() => {
                            match res {
                                Ok(actions) => {
                                    events.extend(
                                        msgs.drain_inbox().iter().map(|m| CoordinatorAuditEvent::MessageReceived(m.clone()))
                                    );
                                    if conditions.iter().all(|c| c.evaluate(&events) == TestOutcome::Passed) {
                                        result.set_outcome(TestOutcome::Passed);
                                        coordinator.shutdown().await.expect("Network to be shutdown");
                                        break;
                                    }
                                    for a in actions {
                                        events.push(CoordinatorAuditEvent::ActionTaken(a.clone()));
                                        let _ = coordinator.execute(a).await;
                                    }
                                    let _outbox = msgs.drain_outbox();
                                }
                                Err(_e) => {}
                            }
                        }
                        shutdown_result = shutdown_rx.changed() => {
                            // Unwrap the potential error with receiving the shutdown token.
                            coordinator.shutdown().await.expect("Network to be shutdown");
                            shutdown_result.expect("The shutdown sender was dropped before the receiver could receive the token");
                            break;
                        }
                    }
                }
                result
            });
        }
        handles
    }

    async fn shutdown(
        self,
        handles: JoinSet<HandleResult>,
        completed: &HashMap<usize, TestOutcome>,
    ) -> HashMap<usize, TestOutcome> {
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
