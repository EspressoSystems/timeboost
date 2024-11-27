use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use timeboost_core::types::message::{Action, Message};
use timeboost_core::types::test::message_interceptor::NetworkMessageInterceptor;
use timeboost_core::{logging, traits::comm::Comm};
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::Group;

pub mod external;
pub mod internal;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CoordinatorAuditEvent {
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
    Failed,
}

#[derive(Clone)]
pub struct TestCondition {
    identifier: String,
    outcome: TestOutcome,
    eval: Arc<dyn Fn(&CoordinatorAuditEvent) -> TestOutcome + Send + Sync>,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new<F>(identifier: String, eval: F) -> Self
    where
        F: for<'a> Fn(&'a CoordinatorAuditEvent) -> TestOutcome + Send + Sync + Clone + 'static,
    {
        Self {
            identifier,
            outcome: TestOutcome::Failed,
            eval: Arc::new(eval),
        }
    }

    pub fn evaluate(&mut self, events: &[CoordinatorAuditEvent]) -> TestOutcome {
        // Only try to evaluate if the test condition has not yet passed
        if self.outcome == TestOutcome::Failed {
            for e in events.iter() {
                let result = (self.eval)(e);
                if result == TestOutcome::Passed {
                    // We are done with this test condition
                    self.outcome = result;
                    break;
                }
            }
        }
        self.outcome
    }
}

/// When we start a test we create a Task Handle for each node
/// This runs the coordinator logic over the `Comm` implementation
/// This will be the result that a task returns for a given node
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TaskHandleResult {
    id: usize,
    outcome: TestOutcome,
}

impl TaskHandleResult {
    pub fn new(id: usize, outcome: TestOutcome) -> Self {
        Self { id, outcome }
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn outcome(&self) -> TestOutcome {
        self.outcome
    }
}

pub trait TestableNetwork {
    type Node: Send;
    type Network: Comm + Send;
    fn new(
        group: Group,
        outcomes: HashMap<usize, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self;
    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>);
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<TaskHandleResult>;
    async fn shutdown(
        self,
        handles: JoinSet<TaskHandleResult>,
        completed: &HashMap<usize, TestOutcome>,
    ) -> HashMap<usize, TestOutcome>;

    fn evaluate(conditions: &mut Vec<TestCondition>, events: &[CoordinatorAuditEvent]) -> bool {
        let mut all_passed = true;
        for c in conditions.iter_mut() {
            if c.evaluate(events) == TestOutcome::Failed {
                all_passed = false;
            }
        }
        all_passed
    }
}

pub struct NetworkTest<N: TestableNetwork> {
    duration: Duration,
    network: N,
}

impl<N: TestableNetwork> NetworkTest<N> {
    pub fn new(
        group: Group,
        outcomes: HashMap<usize, Vec<TestCondition>>,
        duration: Option<Duration>,
        interceptor: NetworkMessageInterceptor,
    ) -> Self {
        Self {
            duration: duration.unwrap_or(Duration::from_secs(4)),
            network: N::new(group, outcomes, interceptor),
        }
    }

    pub async fn run(mut self) {
        logging::init_logging();

        let nodes_and_networks = self.network.init().await;
        let mut handles = self.network.start(nodes_and_networks).await;
        let mut results = HashMap::new();
        let timeout = loop {
            tokio::select! {
                next = handles.join_next() => {
                    match next {
                        Some(result) => {
                            match result {
                                Ok(handle_res) => {
                                    results.insert(handle_res.id(), handle_res.outcome());
                                },
                                Err(err) => {
                                    panic!("Join Err: {}", err);
                                },
                            }
                        },
                        None => break false, // we are done
                    }
                }
                _ = sleep(self.duration) => {
                    break true;
                }
            }
        };

        // Now handle the test result
        if timeout {
            // Shutdown the network for the nodes that did not already complete (hence the timeout)
            // This means that the test will fail
            results.extend(self.network.shutdown(handles, &results).await);
            for (node_id, result) in results {
                if result != TestOutcome::Passed {
                    tracing::error!("Node {} had missing status: {:?}", node_id, result);
                }
            }
            panic!("Test timed out after {:?}", self.duration);
        }

        assert!(
            results
                .values()
                .all(|result| *result == TestOutcome::Passed),
            "Not all nodes passed. Final statuses: {:?}",
            results.values()
        );
    }
}
