use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
};

use anyhow::Result;
use portpicker::pick_unused_port;
use sailfish::sailfish::Sailfish;
use timeboost_core::types::{
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    metrics::ConsensusMetrics,
    test::testnet::TestNet,
    PublicKey,
};
use timeboost_networking::network::{
    client::{derive_libp2p_multiaddr, Libp2pNetwork},
    NetworkNodeConfigBuilder,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

use crate::{tests::network::CoordinatorAuditEvent, Group};

use super::{HandleResult, TestCondition, TestOutcome, TestableNetwork};

pub mod test_simple_network;

pub struct Libp2pNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    outcomes: HashMap<usize, Arc<Vec<TestCondition>>>,
    sf_app_rxs: HashMap<usize, mpsc::Receiver<SailfishStatusEvent>>,
    tb_app_txs: HashMap<usize, mpsc::Sender<TimeboostStatusEvent>>,
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
            sf_app_rxs: HashMap::new(),
            tb_app_txs: HashMap::new(),
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
    ) -> JoinSet<Result<HandleResult, ()>> {
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
            let (sf_app_tx, sf_app_rx) = mpsc::channel(10000);
            let (tb_app_tx, tb_app_rx) = mpsc::channel(10000);

            self.sf_app_rxs.insert(i, sf_app_rx);
            self.tb_app_txs.insert(i, tb_app_tx);

            handles.spawn(async move {
                let net = TestNet::new(network);
                let msgs = net.messages();
                let mut coordinator = node.init(
                    net,
                    (*staked_nodes).clone(),
                    sf_app_tx,
                    tb_app_rx,
                    Arc::new(ConsensusMetrics::default()),
                );

                let mut result = HandleResult::new(i);
                let mut recv_msgs = Vec::new();
                loop {
                    tokio::select! {
                        res = coordinator.next() => {
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
                                        let _ = coordinator.execute(a.clone()).await;
                                    }
                                    let _outbox = msgs.drain_outbox();
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
                Ok(result)
            });
        }
        handles
    }

    async fn shutdown(
        self,
        handles: JoinSet<Result<HandleResult, ()>>,
        completed: HashSet<usize>,
    ) -> Vec<Result<HandleResult, ()>> {
        if handles.is_empty() {
            return Vec::new();
        }
        for (id, send) in self.shutdown_txs.iter() {
            if !completed.contains(id) {
                send.send(()).expect(
                    "The shutdown sender was dropped before the receiver could receive the token",
                );
            }
        }
        handles.join_all().await
    }
}
