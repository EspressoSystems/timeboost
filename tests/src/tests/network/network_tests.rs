use std::{collections::HashMap, time::Duration};

use multisig::PublicKey;
use sailfish::types::RoundNumber;
use timeboost_utils::types::logging;

use crate::Group;
use crate::prelude::*;

use super::message_interceptor::NetworkMessageInterceptor;
use super::{NetworkTest, TestCondition, TestOutcome, TestableNetwork};

pub async fn run_simple_network_genesis_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes).await;

    // Each node should see the initial vertex proposal from every other node.
    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            let conditions: Vec<TestCondition> = group
                .sign_keypairs
                .iter()
                .map(|kpr| {
                    let node_public_key = kpr.public_key();
                    TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            if v.data().round().data().num() == RoundNumber::genesis() + 1
                                && node_public_key == v.data().source().1
                            {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (k.public_key(), conditions)
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
    let group = Group::new(num_nodes).await;
    let rounds = 25;

    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            let conditions: Vec<TestCondition> = group
                .sign_keypairs
                .iter()
                .map(|kpr| {
                    let node_public_key = kpr.public_key();
                    TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            if *v.data().round().data().num() == rounds
                                && node_public_key == v.data().source().1
                            {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (k.public_key(), conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
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
    let group = Group::new(num_nodes).await;
    let committee = group.committee.clone();
    let timeout_round = 3;
    let interceptor = NetworkMessageInterceptor::new(move |msg, _id| {
        if let Message::Vertex(v) = msg {
            let round = msg.round().num();
            // If leader vertex do not process, but process every other so we have 2f + 1
            if *round == timeout_round && *v.signing_key() == committee.leader(*round as usize) {
                return Err("Dropping leader vertex".to_string());
            }
        }
        Ok(msg.clone())
    });

    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            // First only check if we received vertex with no vote cert from leader only
            let committee = group.committee.clone();
            let mut conditions = vec![TestCondition::new(
                "No vote vertex from leader".to_string(),
                move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        let d = v.data();
                        // Ensure vertex has timeout and no vote cert and from round r + 1
                        let no_vote_checks = d.no_vote_cert().is_some()
                            && d.evidence().is_timeout()
                            && *d.round().data().num() == timeout_round + 1;

                        if no_vote_checks {
                            // The signing key needs to be from leader for round `timeout_round + 1`
                            if *v.signing_key() != committee.leader(timeout_round as usize + 1) {
                                return TestOutcome::Failed(
                                    "Should not receive a no vote certificate from non-leader",
                                );
                            }
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Waiting
                },
            )];

            // Next make sure we can advance some rounds and receive all vertices from each node
            conditions.extend(group.sign_keypairs.iter().map(|kpr| {
                let node_public_key = kpr.public_key();
                TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        // Go 20 rounds passed timeout, make sure all nodes receive all vertices
                        // from round
                        if *v.data().round().data().num() == timeout_round + 20
                            && node_public_key == v.data().source().1
                        {
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Waiting
                })
            }));
            (k.public_key(), conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
        interceptor,
    )
    .run()
    .await;
}

pub async fn run_simple_network_round_timeout_genesis_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes).await;
    let committee = group.committee.clone();
    let timeout_round = *RoundNumber::genesis();
    let interceptor = NetworkMessageInterceptor::new(move |msg, _id| {
        if let Message::Vertex(v) = msg {
            let round = msg.round().num();
            // If leader vertex do not process, but process every other so we have 2f + 1
            if *round == timeout_round && *v.signing_key() == committee.leader(*round as usize) {
                return Err("Dropping leader vertex".to_string());
            }
        }
        Ok(msg.clone())
    });

    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            // First only check if we received vertex with no vote cert from leader only
            let committee = group.committee.clone();
            let mut conditions = vec![TestCondition::new(
                "No vote vertex from leader".to_string(),
                move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        let d = v.data();
                        // Ensure vertex has timeout and no vote cert and from round r + 1
                        let no_vote_checks = d.no_vote_cert().is_some()
                            && d.evidence().is_timeout()
                            && *d.round().data().num() == timeout_round + 1;

                        if no_vote_checks {
                            // The signing key needs to be from leader for round `timeout_round + 1`
                            if *v.signing_key() != committee.leader(timeout_round as usize + 1) {
                                return TestOutcome::Failed(
                                    "Should not receive a no vote certificate from non-leader",
                                );
                            }
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Waiting
                },
            )];

            // Next make sure we can advance some rounds and receive all vertices from each node
            conditions.extend(group.sign_keypairs.iter().map(|kpr| {
                let node_public_key = kpr.public_key();
                TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                    if let Some(Message::Vertex(v)) = msg {
                        // Go 20 rounds passed timeout, make sure all nodes receive all vertices
                        // from round
                        if *v.data().round().data().num() == timeout_round + 20
                            && node_public_key == v.data().source().1
                        {
                            return TestOutcome::Passed;
                        }
                    }
                    TestOutcome::Waiting
                })
            }));
            (k.public_key(), conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
        interceptor,
    )
    .run()
    .await;
}

pub async fn run_simple_network_catchup_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes).await;
    let online_at_round = 4;
    let interceptor = NetworkMessageInterceptor::new(move |msg, id| {
        let round = *msg.round().num();
        // Late start 1 node
        if round <= online_at_round && id == 4 {
            return Err(format!("Node: {id}, dropping msg for round: {round}"));
        }
        Ok(msg.clone())
    });

    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            let conditions = group
                .sign_keypairs
                .iter()
                .map(|kpr| {
                    let node_public_key = kpr.public_key();
                    TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            let r = *v.data().round().data().num();
                            if v.data().evidence().is_timeout() && r != 5 {
                                return TestOutcome::Failed(
                                    "We should only timeout when node 4 is leader the first time",
                                );
                            }
                            // Go 10 rounds passed from when the nodes come online
                            // Ensure we receive all vertices even from the node that started late
                            if r == online_at_round + 10 && node_public_key == *v.signing_key() {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (k.public_key(), conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
        interceptor,
    )
    .run()
    .await;
}

pub async fn run_simple_network_catchup_node_missed_round_test<N>()
where
    N: TestableNetwork,
{
    logging::init_logging();

    let num_nodes = 5;
    let group = Group::new(num_nodes).await;
    let offline_at_round = 4;
    let committee = group.committee.clone();
    let node_id = 4;
    let interceptor = NetworkMessageInterceptor::new(move |msg, id| {
        let round = *msg.round().num();
        // Turn node offline for one round
        if round == offline_at_round && id == node_id {
            return Err(format!("Node: {id}, dropping msg for round: {round}"));
        }
        if let Message::Vertex(v) = msg {
            // Simulate coming online in middle of round so drop some vertex messages
            if round == offline_at_round + 1
                && id == node_id
                && (v.signing_key() == committee.get_key(0).unwrap()
                    || v.signing_key() == committee.get_key(1).unwrap()
                    || v.signing_key() == committee.get_key(2).unwrap())
            {
                return Err(format!("Node: {id}, dropping vertex for round: {round}"));
            }
        }

        Ok(msg.clone())
    });

    let node_outcomes: HashMap<PublicKey, Vec<TestCondition>> = group
        .sign_keypairs
        .iter()
        .map(|k| {
            let conditions = group
                .sign_keypairs
                .iter()
                .map(|kpr| {
                    let node_public_key = kpr.public_key();
                    TestCondition::new(format!("Vertex from {}", k.public_key()), move |msg, _a| {
                        if let Some(Message::Vertex(v)) = msg {
                            // Go 10 rounds passed from when the nodes come online
                            // Ensure we receive all vertices even from the node that missed a round
                            let r = *v.data().round().data().num();
                            if r == offline_at_round + 10 && node_public_key == *v.signing_key() {
                                return TestOutcome::Passed;
                            }
                        }
                        TestOutcome::Waiting
                    })
                })
                .collect();
            (k.public_key(), conditions)
        })
        .collect();

    NetworkTest::<N>::new(
        group,
        node_outcomes,
        Some(Duration::from_secs(15)),
        interceptor,
    )
    .run()
    .await;
}
