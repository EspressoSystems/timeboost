use std::collections::HashMap;
use std::time::Duration;

use hotshot::traits::NetworkError;
use sailfish::coordinator::CoordinatorAuditEvent;
use timeboost_core::{logging, traits::comm::Comm};
use tokio::{task::JoinSet, time::timeout};

use crate::Group;

pub mod external;
pub mod internal;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Passed,
    Waiting,
}

pub struct TestCondition {
    identifier: String,
    eval: Box<dyn Fn(&CoordinatorAuditEvent) -> TestOutcome>,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new<F>(identifier: String, eval: F) -> Self
    where
        F: for<'a> Fn(&'a CoordinatorAuditEvent) -> TestOutcome + 'static,
    {
        Self {
            identifier,
            eval: Box::new(eval),
        }
    }

    pub fn evaluate(&self, logs: &[CoordinatorAuditEvent]) -> TestOutcome {
        for e in logs.iter() {
            let result = (self.eval)(e);
            if result != TestOutcome::Waiting {
                return result;
            }
        }

        // We have yet to see the event that we're looking for.
        TestOutcome::Waiting
    }
}

pub trait TestableNetwork {
    type Node: Send;
    type Network: Comm<Err = NetworkError> + Send;
    type Shutdown: Send;
    fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self;
    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>);
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<Self::Shutdown>;
    async fn evaluate(&self) -> HashMap<usize, TestOutcome>;
    async fn shutdown(self, handles: JoinSet<Self::Shutdown>);
}

pub struct NetworkTest<N: TestableNetwork> {
    network: N,
}

impl<N: TestableNetwork> NetworkTest<N> {
    pub fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self {
        Self {
            network: N::new(group, outcomes),
        }
    }

    pub async fn run(mut self) {
        logging::init_logging();

        let nodes_and_networks = self.network.init().await;
        let handles = self.network.start(nodes_and_networks).await;
        let mut st_interim = HashMap::new();

        let final_statuses = match timeout(Duration::from_millis(250), async {
            loop {
                let statuses = self.network.evaluate().await;
                st_interim = statuses.clone();
                if !statuses.values().all(|s| *s == TestOutcome::Passed) {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    tokio::task::yield_now().await;
                } else {
                    return statuses;
                }
            }
        })
        .await
        {
            Ok(statuses) => statuses,
            Err(_) => {
                for (node_id, status) in st_interim.iter() {
                    if *status != TestOutcome::Passed {
                        tracing::error!("Node {} had missing status: {:?}", node_id, status);
                    }
                }

                panic!("Test timed out after 250ms")
            }
        };

        self.network.shutdown(handles).await;

        // Now verify all statuses are Passed
        assert!(
            final_statuses.values().all(|s| *s == TestOutcome::Passed),
            "Not all nodes passed. Final statuses: {:?}",
            final_statuses
        );
    }
}
