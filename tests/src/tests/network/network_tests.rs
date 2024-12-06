use std::{collections::HashMap, time::Duration};

use timeboost_core::{
    logging,
    types::{message::Message, test::message_interceptor::NetworkMessageInterceptor},
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::School;

use super::{NetworkTest, TestCondition, TestOutcome, TestableNetwork};

pub async fn run_simple_network_genesis_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = School::new(num_nodes as u16);
    // Each node should see the initial vertex proposal from every other node.
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|n| {
                    let node_public_key = *n.public_key();
                    TestCondition::new(format!("Vertex from {}", node_id), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            if v.data().round() == RoundNumber::genesis() + 1
                                && node_public_key == *v.data().source()
                            {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Failed
                    })
                })
                .collect();
            (node_id, conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        None,
        NetworkMessageInterceptor::default(),
    )
    .run()
    .await;
}

pub async fn run_network_round_progression_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = School::new(num_nodes as u16);
    let rounds = 25;

    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|n| {
                    let node_public_key = *n.public_key();
                    TestCondition::new(format!("Vertex from {}", node_id), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            if *v.data().round() == rounds && node_public_key == *v.data().source()
                            {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Failed
                    })
                })
                .collect();
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(300)),
        NetworkMessageInterceptor::default(),
    )
    .run()
    .await;
}

pub async fn run_simple_network_round_timeout_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = School::new(num_nodes as u16);
    let committee = group.committee.clone();
    let timeout_round = 3;
    let interceptor = NetworkMessageInterceptor::new(move |msg| {
        if let Message::Vertex(v) = msg {
            let round = msg.round();
            // If leader vertex do not process, but process every other so we have 2f + 1
            if *round == timeout_round && *v.signing_key() == committee.leader(round) {
                return Err("Dropping leader vertex");
            }
        }
        Ok(msg.clone())
    });

    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            // First only check if we received vertex with no vote cert from leader only
            let committee = group.committee.clone();
            let mut conditions = vec![TestCondition::new(
                "No vote vertex from leader".to_string(),
                move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        let d = v.data();
                        // Ensure vertex has timeout and no vote cert and from round r + 1
                        let no_vote_checks = d.no_vote_cert().is_some()
                            && d.timeout_cert().is_some()
                            && *d.round() == timeout_round + 1;

                        if no_vote_checks {
                            // The signing key needs to be from leader for round `timeout_round + 1``
                            if *v.signing_key() != committee.leader((timeout_round + 1).into()) {
                                panic!("Should not receive a no vote from non leader");
                            }
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Failed
                },
            )];

            // Next make sure we can advance some rounds and receive all vertices from each node
            conditions.extend(group.fish.iter().map(|n| {
                let node_public_key = *n.public_key();
                TestCondition::new(format!("Vertex from {}", node_id), move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        // Go 20 rounds passed timeout, make sure all nodes receive all vertices from round
                        if *v.data().round() == timeout_round + 20
                            && node_public_key == *v.data().source()
                        {
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Failed
                })
            }));
            (node_id as usize, conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(300)),
        interceptor,
    )
    .run()
    .await;
}
