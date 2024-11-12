use std::{collections::HashMap, time::Duration};

use sailfish::coordinator_helpers::{
    interceptor::NetworkMessageInterceptor, test_coordinator::CoordinatorAuditEvent,
};
use timeboost_core::{
    logging,
    types::{message::Message, round_number::RoundNumber},
};

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
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|n| {
                    let node_public_key = *n.public_key();
                    TestCondition::new(format!("Vertex from {}", node_id), move |e| {
                        if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                            if *v.data().round().data() == RoundNumber::genesis()
                                && node_public_key == *v.data().source()
                            {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<Libp2pNetworkTest>::new(
        group,
        node_outcomes,
        None,
        NetworkMessageInterceptor::default(),
    )
    .run()
    .await;
}

#[tokio::test]
async fn test_simple_network_round_progression() {
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes as u16);
    let rounds = 50;
    // Each node should see the initial vertex proposal from every other node.
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|_n| {
                    TestCondition::new(format!("Vertex from {}", node_id), move |e| {
                        if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                            if *v.data().round().data() == rounds.into() {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<Libp2pNetworkTest>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
        NetworkMessageInterceptor::default(),
    )
    .run()
    .await;
}

#[tokio::test]
async fn test_simple_network_round_timeout() {
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes as u16);
    let interceptor = NetworkMessageInterceptor::new(move |msg, committee| {
        if let Message::Vertex(v) = msg {
            let round = msg.round();
            if *round == 6 && *v.signing_key() == committee.leader(round) {
                return vec![];
            }
        }
        vec![msg.clone()]
    });
    // Each node should see the initial vertex proposal from every other node.
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|_n| {
                    TestCondition::new(format!("Vertex from {}", node_id), move |e| {
                        if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                            if v.data().no_vote_cert().is_some() {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<Libp2pNetworkTest>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(10)),
        interceptor,
    )
    .run()
    .await;
}
