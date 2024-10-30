use std::{collections::HashMap, sync::Arc};

use crate::Group;

use super::{NetworkTest, TestCondition, TestOutcome};
use async_lock::RwLock;
use sailfish::{
    coordinator::{Coordinator, CoordinatorAuditEvent},
    sailfish::ShutdownToken,
};
use timeboost_core::types::test::net::Star;
use tokio::{
    sync::oneshot::{self, Receiver, Sender},
    task::JoinSet,
};

pub mod test_simple_network;

pub struct MemoryNetworkTest {
    group: Group,
    shutdown_txs: HashMap<usize, Sender<ShutdownToken>>,
    shutdown_rxs: HashMap<usize, Receiver<ShutdownToken>>,
    event_logs: HashMap<usize, Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    outcomes: HashMap<usize, Vec<TestCondition>>,
}

impl MemoryNetworkTest {
    pub fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self {
        let (shutdown_txs, shutdown_rxs): (
            Vec<Sender<ShutdownToken>>,
            Vec<Receiver<ShutdownToken>>,
        ) = (0..group.fish.len()).map(|_| oneshot::channel()).unzip();
        let event_logs = HashMap::from_iter(
            (0..group.fish.len()).map(|i| (i, Arc::new(RwLock::new(Vec::new())))),
        );
        Self {
            group,
            shutdown_txs: HashMap::from_iter(shutdown_txs.into_iter().enumerate()),
            shutdown_rxs: HashMap::from_iter(shutdown_rxs.into_iter().enumerate()),
            outcomes,
            event_logs,
        }
    }
}

impl NetworkTest for MemoryNetworkTest {
    type Node = Coordinator;
    type Network = Star<Vec<u8>>;
    type Shutdown = ShutdownToken;

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut net = Star::new();
        let mut coordinators = Vec::new();
        for (i, n) in std::mem::take(&mut self.group.fish).into_iter().enumerate() {
            let shutdown_rx = self
                .shutdown_rxs
                .remove(&i)
                .unwrap_or_else(|| panic!("No shutdown receiver available for node {}", i));

            // Join each node to the network
            let ch = net.join(*n.public_key());

            // Initialize the coordinator
            let co = n.init(
                ch,
                (*self.group.staked_nodes).clone(),
                shutdown_rx,
                Some(Arc::clone(&self.event_logs[&i])),
            );

            tracing::debug!("Started coordinator {}", i);
            coordinators.push(co);
        }

        (coordinators, vec![net])
    }

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<Self::Shutdown> {
        let mut co_handles = JoinSet::new();
        // There's always only one network for the memory network test.
        let (coordinators, mut nets) = nodes_and_networks;
        for co in coordinators {
            co_handles.spawn(co.go());
        }

        let net = nets.pop().expect("memory network to be present");
        tokio::spawn(net.run());

        co_handles
    }

    async fn evaluate(&self) -> HashMap<usize, TestOutcome> {
        let mut statuses =
            HashMap::from_iter(self.outcomes.keys().map(|k| (*k, TestOutcome::Waiting)));
        for (node_id, conditions) in self.outcomes.iter() {
            tracing::info!("Evaluating node {}", node_id);
            let log = self.event_logs.get(node_id).unwrap().read().await;
            let eval_result: Vec<TestOutcome> =
                conditions.iter().map(|c| c.evaluate(&log)).collect();

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
            let _ = send.send(ShutdownToken::new());
        }
        handles.join_all().await;
    }
}
