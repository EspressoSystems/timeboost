use std::{collections::HashMap, sync::Arc};

use std::time::Duration;
use timeboost_core::{
    logging,
    types::{message::Message, round_number::RoundNumber},
};

use crate::tests::network::CoordinatorAuditEvent;
use crate::{
    tests::network::{external::Libp2pNetworkTest, NetworkTest, TestCondition, TestOutcome},
    Group,
};

#[tokio::test]
async fn test_simple_network_genesis() {
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes as u16);
    // Each node should see the initial vertex proposal from every other node.
    let node_outcomes: HashMap<usize, Arc<Vec<TestCondition>>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Arc<Vec<TestCondition>> = Arc::new(
                group
                    .fish
                    .iter()
                    .map(|n| {
                        let node_public_key = *n.public_key();
                        TestCondition::new(format!("Vertex from {}", node_id), move |e| {
                            if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                                if v.data().round() == RoundNumber::genesis() + 1
                                    && node_public_key == *v.data().source()
                                {
                                    return TestOutcome::Passed;
                                }
                            }
                            TestOutcome::Failed
                        })
                    })
                    .collect(),
            );
            (node_id, conditions)
        })
        .collect();

    NetworkTest::<Libp2pNetworkTest>::new(group, node_outcomes, None)
        .run()
        .await;
}

#[tokio::test]
async fn test_simple_network_round_progression() {
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes as u16);
    let rounds = 50;
    // Each node should see all vertex proposals up to `rounds`
    let node_outcomes: HashMap<usize, Arc<Vec<TestCondition>>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Arc<Vec<TestCondition>> = Arc::new(
                group
                    .fish
                    .iter()
                    .map(|_n| {
                        TestCondition::new(format!("Vertex from {}", node_id), move |e| {
                            if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                                if v.data().round() == rounds.into() {
                                    return TestOutcome::Passed;
                                }
                            }
                            TestOutcome::Failed
                        })
                    })
                    .collect(),
            );
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<Libp2pNetworkTest>::new(group, node_outcomes, Some(Duration::from_secs(300)))
        .run()
        .await;
}
