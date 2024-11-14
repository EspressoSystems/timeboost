use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use crate::Group;

use super::{CoordinatorAuditEvent, TestCondition, TestOutcome, TestableNetwork};
use async_lock::RwLock;
use futures::future::BoxFuture;
use futures::FutureExt;
use sailfish::coordinator::Coordinator;
use std::future::pending;
use timeboost_core::types::{
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    message::Message,
    round_number::RoundNumber,
    test::net::{Conn, Star},
};
use tokio::{sync::mpsc, task::JoinSet};

pub mod test_simple_network;

pub struct MemoryNetworkTest {
    group: Group,
    event_logs: HashMap<usize, Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    outcomes: HashMap<usize, Vec<TestCondition>>,
    sf_app_rxs: HashMap<usize, mpsc::Receiver<SailfishStatusEvent>>,
    tb_app_txs: HashMap<usize, mpsc::Sender<TimeboostStatusEvent>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl TestableNetwork for MemoryNetworkTest {
    type Node = Coordinator<Conn<Message>>;
    type Network = Star<Message>;

    fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self {
        let event_logs = HashMap::from_iter(
            (0..group.fish.len()).map(|i| (i, Arc::new(RwLock::new(Vec::new())))),
        );
        Self {
            group,
            outcomes,
            event_logs,
            sf_app_rxs: HashMap::new(),
            tb_app_txs: HashMap::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        // This is intentionally *not* a member of the struct due to `run` consuming
        // the instance.
        let mut net = Star::new();
        let mut coordinators = Vec::new();
        for (i, n) in std::mem::take(&mut self.group.fish).into_iter().enumerate() {
            // Join each node to the network
            let ch = net.join(*n.public_key());

            let (sf_app_tx, sf_app_rx) = mpsc::channel(10000);
            let (tb_app_tx, tb_app_rx) = mpsc::channel(10000);

            self.sf_app_rxs.insert(i, sf_app_rx);
            self.tb_app_txs.insert(i, tb_app_tx);

            // Initialize the coordinator
            let co = n.init(ch, (*self.group.staked_nodes).clone(), sf_app_tx, tb_app_rx);

            tracing::debug!("Started coordinator {}", i);
            coordinators.push(co);
        }

        (coordinators, vec![net])
    }

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<()> {
        let mut co_handles = JoinSet::new();
        // There's always only one network for the memory network test.
        let (coordinators, mut nets) = nodes_and_networks;

        for (i, mut co) in coordinators.into_iter().enumerate() {
            let shutdown = Arc::clone(&self.shutdown_flag);
            let mut log = Arc::clone(self.event_logs.get(&i).unwrap());
            co_handles.spawn(async move {
                let mut timer: BoxFuture<'static, RoundNumber> = pending().boxed();
                co.start(&mut timer).await;
                loop {
                    Self::go2(&mut co, &mut log, &mut timer).await;
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                }
                tracing::error!("shutdown");
            });
        }

        let net = nets.pop().expect("memory network to be present");
        let shutdown = Arc::clone(&self.shutdown_flag);
        tokio::spawn(async move { net.run(shutdown).await });

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

    async fn shutdown(self, handles: JoinSet<()>) {
        self.shutdown_flag.store(true, Ordering::Relaxed);

        // Wait for all the coordinators to shutdown
        handles.join_all().await;
    }
}
