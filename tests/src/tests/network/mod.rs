use async_trait::async_trait;
use std::{collections::HashMap, num::NonZeroUsize, pin::Pin, sync::Arc};

use async_lock::RwLock;
use hotshot::traits::{
    implementations::{derive_libp2p_keypair, derive_libp2p_multiaddr, Libp2pNetwork},
    NetworkError, NetworkNodeConfigBuilder,
};
use portpicker::pick_unused_port;
use sailfish::{
    coordinator::CoordinatorAuditEvent,
    sailfish::Sailfish,
    types::{comm::Comm, PublicKey},
};
use tokio::{
    sync::oneshot::{self, Receiver, Sender},
    task::JoinSet,
};

use crate::{net::Star, Group};

pub mod external;
pub mod internal;

#[async_trait]
trait NetworkTest {
    fn new(&self, node_id: usize, group: Group) -> Self;
    async fn init(&mut self)
        -> Vec<(Sailfish, Box<dyn Comm<Err = NetworkError> + Send + 'static>)>;
    async fn start(
        &self,
        networks: Vec<(Sailfish, Box<dyn Comm<Err = NetworkError> + Send + 'static>)>,
    );
}

pub struct MemoryNetworkTest {
    network: Star<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Passed,
    Waiting,
}

impl std::fmt::Display for TestOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
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
    pub fn new(
        identifier: String,
        eval: Box<dyn Fn(&CoordinatorAuditEvent) -> TestOutcome>,
    ) -> Self {
        Self { identifier, eval }
    }

    pub fn evaluate(&self, logs: &Vec<CoordinatorAuditEvent>) -> TestOutcome {
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
