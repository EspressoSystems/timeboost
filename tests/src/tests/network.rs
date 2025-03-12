use std::collections::HashMap;
use std::time::Duration;

use multisig::PublicKey;
use sailfish::Coordinator;
use sailfish::types::Comm;
use timeboost_utils::test::message_interceptor::NetworkMessageInterceptor;
use timeboost_utils::test::testnet::MsgQueues;
use timeboost_utils::types::logging;
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::Group;
use crate::prelude::*;

mod rbc;

pub mod external;
pub mod internal;
pub mod network_tests;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Waiting,
    Timeout,
    Passed,
    Failed(&'static str),
}

type TestConditionFn = Box<dyn Fn(Option<&Message>, Option<&Action>) -> TestOutcome + Send + Sync>;
pub struct TestCondition {
    identifier: String,
    outcome: TestOutcome,
    eval: TestConditionFn,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new<F>(identifier: String, eval: F) -> Self
    where
        F: for<'a, 'b> Fn(Option<&'a Message>, Option<&'b Action>) -> TestOutcome
            + Send
            + Sync
            + 'static,
    {
        Self {
            identifier,
            outcome: TestOutcome::Waiting,
            eval: Box::new(eval),
        }
    }

    pub fn evaluate(&mut self, msgs: &[Message], actions: &[Action]) -> TestOutcome {
        // Only try to evaluate if the test condition has not yet passed
        if self.outcome == TestOutcome::Waiting {
            for m in msgs.iter() {
                let result = (self.eval)(Some(m), None);
                if result != TestOutcome::Waiting {
                    // We are done with this test condition
                    self.outcome = result;
                    return result;
                }
            }

            for a in actions.iter() {
                let result = (self.eval)(None, Some(a));
                if result != TestOutcome::Waiting {
                    // We are done with this test condition
                    self.outcome = result;
                    return result;
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
pub(crate) struct TaskHandleResult {
    key: PublicKey,
    outcome: TestOutcome,
}

impl TaskHandleResult {
    pub(crate) fn new(key: PublicKey, outcome: TestOutcome) -> Self {
        Self { key, outcome }
    }
}

pub trait TestableNetwork {
    type Node: Send;
    type Network: Comm<SailfishBlock> + Send + 'static;

    fn new(
        group: Group,
        outcomes: HashMap<PublicKey, Vec<TestCondition>>,
        interceptor: NetworkMessageInterceptor<SailfishBlock>,
    ) -> Self;

    fn public_key(&self, n: &Self::Node) -> PublicKey;

    async fn init(&mut self) -> Vec<Self::Node>;

    async fn start(&mut self, nodes: Vec<Self::Node>) -> JoinSet<TaskHandleResult>;

    /// Default method for running the coordinator in tests
    async fn run_coordinator(
        coordinator: &mut Coordinator<SailfishBlock, Self::Network>,
        conditions: &mut Vec<TestCondition>,
        msgs: MsgQueues<SailfishBlock>,
    ) -> TaskHandleResult {
        for a in coordinator.init() {
            let _ = coordinator.execute(a).await;
        }
        loop {
            match coordinator.next().await {
                Ok(actions) => {
                    for a in &actions {
                        let _ = coordinator.execute(a.clone()).await;
                    }
                    // Evaluate if we have seen the specified conditions of the test
                    // Go through every test condition and evaluate
                    // Do not terminate loop early to ensure we evaluate all
                    let mut outcome = TestOutcome::Passed;
                    let mut all_evaluated = true;
                    let msgs = msgs.drain_inbox();
                    for c in conditions.iter_mut() {
                        match c.evaluate(&msgs, &actions) {
                            TestOutcome::Failed(reason) => {
                                // If any failed, the test has failed
                                outcome = TestOutcome::Failed(reason);
                            }
                            TestOutcome::Waiting => {
                                all_evaluated = false;
                            }
                            _ => {}
                        }
                    }
                    if all_evaluated {
                        // We are done with this nodes test, we can break our loop and pop off `JoinSet` handles
                        sleep(Duration::from_secs(1)).await;
                        return TaskHandleResult::new(coordinator.public_key(), outcome);
                    }
                }
                Err(e) => {
                    tracing::warn!("Coordinator Error: {}", e)
                }
            }
        }
    }
}

pub struct NetworkTest<N: TestableNetwork> {
    duration: Duration,
    network: N,
}

impl<N: TestableNetwork> NetworkTest<N> {
    pub fn new(
        group: Group,
        outcomes: HashMap<PublicKey, Vec<TestCondition>>,
        duration: Option<Duration>,
        interceptor: NetworkMessageInterceptor<SailfishBlock>,
    ) -> Self {
        Self {
            duration: duration.unwrap_or(Duration::from_secs(4)),
            network: N::new(group, outcomes, interceptor),
        }
    }

    pub async fn run(mut self) {
        logging::init_logging();

        let nodes_and_networks = self.network.init().await;

        let mut results = HashMap::new();

        // Default to timeout for each node
        for key in nodes_and_networks
            .iter()
            .map(|c| self.network.public_key(c))
        {
            results.insert(key, TestOutcome::Timeout);
        }

        let mut handles = self.network.start(nodes_and_networks).await;

        let timeout = loop {
            tokio::select! {
                next = handles.join_next() => {
                    match next {
                        Some(result) => {
                            match result {
                                Ok(handle_res) => {
                                    results.insert(handle_res.key, handle_res.outcome);
                                },
                                Err(err) => {
                                    panic!("Join Err: {}", err);
                                },
                            }
                        },
                        None => break false,
                    }
                }
                _ = sleep(self.duration) => {
                    break true;
                }
            }
        };

        if timeout {
            // Stop tasks and print results
            handles.abort_all();
            for (node_id, result) in results {
                if result != TestOutcome::Passed {
                    tracing::error!("Node {} had status: {:?}", node_id, result);
                }
            }
            panic!("Test timed out after {:?}", self.duration);
        }

        assert!(
            results
                .values()
                .all(|result| *result == TestOutcome::Passed),
            "Not all nodes passed. Final statuses: {:#?}",
            results.values()
        );
    }
}
