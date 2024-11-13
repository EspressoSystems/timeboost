use std::{collections::HashMap, fmt::Debug, time::Duration};

use sailfish::coordinator::CoordinatorAuditEvent;
use timeboost_core::{logging, traits::comm::Comm, types::event::SailfishStatusEvent};
use tokio::{task::JoinSet, time::timeout};

use crate::Group;

pub mod external;
pub mod internal;

const TEST_APP_LAYER_CHANNEL_DEPTH: usize = 10_000;
const TEST_APP_LAYER_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Passed,
    Waiting,
}

struct EventEvaluator<T: Debug> {
    eval: Box<dyn Fn(&T) -> TestOutcome>,
}

impl<T: Debug> Default for EventEvaluator<T> {
    fn default() -> Self {
        Self::new(|e| {
            panic!(
                "No defined evaluator, but received an event which must be evaluated: {:?}",
                e
            )
        })
    }
}

impl<T: Debug> EventEvaluator<T> {
    pub fn new<F>(eval: F) -> Self
    where
        F: for<'a> Fn(&'a T) -> TestOutcome + 'static,
    {
        Self {
            eval: Box::new(eval),
        }
    }
}

pub struct TestCondition {
    identifier: String,
    event_eval: EventEvaluator<CoordinatorAuditEvent>,
    app_eval: EventEvaluator<SailfishStatusEvent>,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new(
        identifier: String,
        event_eval: EventEvaluator<CoordinatorAuditEvent>,
        app_eval: EventEvaluator<SailfishStatusEvent>,
    ) -> Self {
        Self {
            identifier,
            event_eval,
            app_eval,
        }
    }

    pub fn evaluate(
        &self,
        logs: &[CoordinatorAuditEvent],
        app_msgs: &[SailfishStatusEvent],
    ) -> TestOutcome {
        for e in logs.iter() {
            let result = (self.event_eval)(e);
            if result != TestOutcome::Waiting {
                return result;
            }
        }

        for e in app_msgs.iter() {
            let result = (self.event_eval)(e);
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
    type Network: Comm + Send;
    type Shutdown: Send;
    fn new(group: Group, outcomes: HashMap<usize, Vec<TestCondition>>) -> Self;
    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>);
    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> JoinSet<Self::Shutdown>;
    async fn evaluate(&mut self) -> HashMap<usize, TestOutcome>;
    async fn shutdown(self, handles: JoinSet<Self::Shutdown>);
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
    ) -> Self {
        Self {
            duration: duration.unwrap_or(Duration::from_secs(4)),
            network: N::new(group, outcomes),
        }
    }

    pub async fn run(mut self) {
        logging::init_logging();

        let nodes_and_networks = self.network.init().await;
        let mut st_interim = HashMap::new();
        let handles = self.network.start(nodes_and_networks).await;

        // Run the test, evaluating the statuses of the nodes until all have passed, or the test times out.
        let result = timeout(self.duration, async {
            loop {
                let statuses = self.network.evaluate().await;
                st_interim = statuses.clone();
                if !statuses.values().all(|s| *s == TestOutcome::Passed) {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    tokio::task::yield_now().await;
                } else {
                    break statuses;
                }
            }
        })
        .await;

        // Always shutdown the network.
        self.network.shutdown(handles).await;

        // Now handle the test result
        match result {
            Ok(st) => {
                // We pretty much won't get here as we'd timeout before this would break and return,
                // but we keep this check as a backstop.
                assert!(
                    st.values().all(|s| *s == TestOutcome::Passed),
                    "Not all nodes passed. Final statuses: {:?}",
                    st
                );
            }
            Err(_) => {
                for (node_id, status) in st_interim.iter() {
                    if *status != TestOutcome::Passed {
                        tracing::error!("Node {} had missing status: {:?}", node_id, status);
                    }
                }
                panic!("Test timed out after {:?}", self.duration);
            }
        };
    }
}
