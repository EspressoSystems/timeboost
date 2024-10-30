use std::{collections::HashMap, sync::Arc};

use crate::{net::Star, Group};

use super::{TestCondition, TestOutcome};
use async_lock::RwLock;
use sailfish::{
    coordinator::{Coordinator, CoordinatorAuditEvent},
    sailfish::ShutdownToken,
};
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
    coordinators: JoinSet<ShutdownToken>,
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
            coordinators: JoinSet::new(),
        }
    }

    pub async fn init(&mut self) -> (Vec<Coordinator>, Star<Vec<u8>>) {
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

        (coordinators, net)
    }

    pub async fn start(&mut self, cos_and_net: (Vec<Coordinator>, Star<Vec<u8>>)) {
        let (coordinators, net) = cos_and_net;
        for co in coordinators {
            self.coordinators.spawn(co.go());
        }

        tokio::spawn(net.run());
    }

    pub async fn evaluate(&self) -> HashMap<usize, TestOutcome> {
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

    pub async fn shutdown(self) {
        for send in self.shutdown_txs.into_values() {
            let _ = send.send(ShutdownToken::new());
        }
        self.coordinators.join_all().await;
    }
}
