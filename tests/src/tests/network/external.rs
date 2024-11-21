use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

use anyhow::{anyhow, Result};
use async_lock::RwLock;
use portpicker::pick_unused_port;
use sailfish::{coordinator::CoordinatorAuditEvent, sailfish::Sailfish};
use timeboost_core::traits::comm::Libp2p;
use timeboost_core::types::{
    committee::StaticCommittee,
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    metrics::ConsensusMetrics,
};
use timeboost_networking::network::{client::derive_libp2p_multiaddr, NetworkNodeConfigBuilder};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

use crate::Group;

use super::{TestCondition, TestOutcome, TestableNetwork};

pub mod test_simple_network;

pub struct Libp2pNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, watch::Sender<()>>,
    shutdown_rxs: HashMap<usize, watch::Receiver<()>>,
    event_logs: HashMap<usize, Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    outcomes: HashMap<usize, Vec<TestCondition>>,
    sf_app_rxs: HashMap<usize, mpsc::Receiver<SailfishStatusEvent>>,
    tb_app_txs: HashMap<usize, mpsc::Sender<TimeboostStatusEvent>>,
}

impl TestableNetwork for Libp2pNetworkTest {
    type Node = Sailfish;
    type Network = Libp2p;
    type Shutdown = Result<()>;

    fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self {
        let (shutdown_txs, shutdown_rxs): (Vec<watch::Sender<()>>, Vec<watch::Receiver<()>>) =
            (0..group.fish.len()).map(|_| watch::channel(())).unzip();
        let event_logs = HashMap::from_iter(
            (0..group.fish.len()).map(|i| (i, Arc::new(RwLock::new(Vec::new())))),
        );

        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            event_logs,
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

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<Self::Shutdown> {
        let mut handles = JoinSet::new();
        let (nodes, networks) = nodes_and_networks;

        assert_eq!(
            nodes.len(),
            networks.len(),
            "Nodes and networks vectors must be the same length"
        );

        for (i, (node, network)) in nodes.into_iter().zip(networks).enumerate() {
            let staked_nodes = Arc::clone(&self.group.staked_nodes);
            let log = Arc::clone(self.event_logs.get(&i).unwrap());
            let shutdown_rx = self.shutdown_rxs.remove(&i).unwrap();
            let (sf_app_tx, sf_app_rx) = mpsc::channel(10000);
            let (tb_app_tx, tb_app_rx) = mpsc::channel(10000);

            self.sf_app_rxs.insert(i, sf_app_rx);
            self.tb_app_txs.insert(i, tb_app_tx);

            handles.spawn(async move {
                let co = node.init(
                    network,
                    (*staked_nodes).clone(),
                    sf_app_tx,
                    tb_app_rx,
                    Arc::new(ConsensusMetrics::default()),
                    Some(Arc::clone(&log)),
                );

                co.go(shutdown_rx).await.map_err(|e| anyhow!(e))
            });
        }
        handles
    }

    async fn evaluate(&self) -> HashMap<usize, TestOutcome> {
        let mut statuses =
            HashMap::from_iter(self.outcomes.keys().map(|k| (*k, TestOutcome::Waiting)));
        for (node_id, conditions) in self.outcomes.iter() {
            tracing::info!("Evaluating node {}", node_id);
            let log = self.event_logs.get(node_id).unwrap().read().await;
            let eval_result: Vec<TestOutcome> =
                conditions.iter().map(|c| c.evaluate(&log)).collect();

            // TODO: Add the application layer statuses to the evaluation criteria.

            // If any of the conditions are Waiting or Failed, then set the status to that, otherwise
            // set it to Passed.
            let status = eval_result.iter().fold(TestOutcome::Passed, |acc, x| {
                if *x == TestOutcome::Waiting {
                    *x
                } else {
                    acc
                }
            });

            *statuses.get_mut(node_id).expect("Node ID not found") = status;
        }

        statuses
    }

    async fn shutdown(self, handles: JoinSet<Self::Shutdown>) {
        for send in self.shutdown_txs.into_values() {
            send.send(()).expect(
                "The shutdown sender was dropped before the receiver could receive the token",
            );
        }
        handles.join_all().await;
    }
}
