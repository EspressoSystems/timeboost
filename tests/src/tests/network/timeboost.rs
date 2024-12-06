use std::collections::HashMap;

use crate::School;

use super::{TestCondition, TestableNetwork};
use sailfish::rbc::Rbc;
use timeboost::Timeboost;
use timeboost_core::types::test::{
    message_interceptor::NetworkMessageInterceptor, testnet::TestNet,
};

pub struct TimeboostTest {
    group: School,
    outcomes: HashMap<usize, Vec<TestCondition>>,
    interceptor: NetworkMessageInterceptor,
}

impl TestableNetwork for TimeboostTest {
    type Node = Timeboost;

    type Network = Rbc;

    type Testnet = TestNet<Self::Network>;

    fn new(
        group: crate::School,
        outcomes: std::collections::HashMap<usize, Vec<super::TestCondition>>,
        interceptor: timeboost_core::types::test::message_interceptor::NetworkMessageInterceptor,
    ) -> Self {
        todo!()
    }

    async fn init(&mut self) -> (Vec<Self::Node>, Vec<Self::Network>) {
        todo!()
    }

    async fn start(
        &mut self,
        nodes_and_networks: (Vec<Self::Node>, Vec<Self::Network>),
    ) -> tokio::task::JoinSet<super::TaskHandleResult> {
        todo!()
    }

    async fn shutdown(
        self,
        handles: tokio::task::JoinSet<super::TaskHandleResult>,
        completed: &std::collections::HashMap<usize, super::TestOutcome>,
    ) -> std::collections::HashMap<usize, super::TestOutcome> {
        todo!()
    }
}
