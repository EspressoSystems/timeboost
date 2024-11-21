use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use timeboost_core::types::message::{Action, Message};
use timeboost_core::{logging, traits::comm::Comm};
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::Group;

pub mod external;
pub mod internal;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CoordinatorAuditEvent {
    #[allow(unused)]
    ActionTaken(Action),
    MessageReceived(Message),
}

impl std::fmt::Display for CoordinatorAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionTaken(a) => write!(f, "Action taken: {a}"),
            Self::MessageReceived(m) => write!(f, "Message received: {m}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Passed,
    Waiting,
}

pub struct TestCondition {
    identifier: String,
    eval: Box<dyn Fn(&CoordinatorAuditEvent) -> TestOutcome + Send + Sync>,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new<F>(identifier: String, eval: F) -> Self
    where
        F: for<'a> Fn(&'a CoordinatorAuditEvent) -> TestOutcome + Send + Sync + 'static,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HandleResult {
    id: usize,
    outcome: TestOutcome,
}

impl HandleResult {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            outcome: TestOutcome::Waiting,
        }
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn outcome(&self) -> TestOutcome {
        self.outcome
    }

    pub fn set_outcome(&mut self, outcome: TestOutcome) {
        self.outcome = outcome;
    }
}

pub trait TestableNetwork {
    type Node: Send;
    type Network: Comm + Send;
    fn new(group: Group, outcomes: HashMap<usize, Arc<Vec<TestCondition>>>) -> Self;
    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>);
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<HandleResult>;
    async fn shutdown(
        self,
        handles: JoinSet<HandleResult>,
        completed: &HashMap<usize, HandleResult>,
    ) -> HashMap<usize, HandleResult>;
}

pub struct NetworkTest<N: TestableNetwork> {
    duration: Duration,
    network: N,
}

impl<N: TestableNetwork> NetworkTest<N> {
    pub fn new(
        group: Group,
        outcomes: HashMap<usize, Arc<Vec<TestCondition>>>,
        duration: Option<Duration>,
    ) -> Self {
        Self {
            duration: duration.unwrap_or(Duration::from_secs(4)),
            network: N::new(group, outcomes),
        }
    }

    pub async fn run(mut self) {
        logging::init_logging();

        let nodes_and_networks = self.network.init().await;
        let mut handles = self.network.start(nodes_and_networks).await;
        let mut results = HashMap::new();
        loop {
            tokio::select! {
                next = handles.join_next() => {
                    match next {
                        Some(result) => {
                            match result {
                                Ok(handle_res) => {
                                    results.insert(handle_res.id(), handle_res);
                                },
                                Err(err) => {
                                    panic!("Join Err: {}", err);
                                },
                            }
                        },
                        None => break, // we are done
                    }
                }
                _ = sleep(self.duration) => {
                    break;
                }
            }
        }

        // Always shutdown the network.
        results.extend(self.network.shutdown(handles, &results).await);

        // Now handle the test result
        for (id, result) in results {
            assert_eq!(
                result.outcome(),
                TestOutcome::Passed,
                "Node id: {} failed. Test is waiting",
                id
            );
        }
    }
}
