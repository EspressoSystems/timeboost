use std::collections::HashMap;

use sailfish::coordinator::CoordinatorAuditEvent;
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
    // Each node should see the genesis vertex from every other node.
    let node_outcomes: HashMap<usize, Vec<TestCondition>> = (0..num_nodes)
        .map(|node_id| {
            let conditions: Vec<TestCondition> = group
                .fish
                .iter()
                .map(|n| {
                    let node_public_key = *n.public_key();
                    TestCondition::new(format!("Genesis Vertex from {}", node_id), move |e| {
                        if let CoordinatorAuditEvent::MessageReceived(Message::Vertex(v)) = e {
                            if v.data().id().round() == RoundNumber::genesis()
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

    NetworkTest::<Libp2pNetworkTest>::new(group, node_outcomes, None)
        .run()
        .await;
}
