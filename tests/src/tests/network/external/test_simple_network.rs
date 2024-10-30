use std::collections::HashMap;

use sailfish::coordinator::CoordinatorAuditEvent;
use timeboost_core::{
    logging,
    types::{message::Message, round_number::RoundNumber},
};
use tokio::time::{timeout, Duration};

use crate::{
    tests::network::{external::Libp2pNetworkTest, TestCondition, TestOutcome},
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
            (node_id, conditions)
        })
        .collect();

    let mut test = Libp2pNetworkTest::new(group, node_outcomes);
    let networks = test.init().await;
    let test_handles = test.start(networks).await;

    let mut st_interim = HashMap::new();
    let final_statuses = match timeout(Duration::from_millis(250), async {
        loop {
            let statuses = test.evaluate().await;
            st_interim = statuses.clone();
            if !statuses.values().all(|s| *s == TestOutcome::Passed) {
                tokio::time::sleep(Duration::from_millis(2)).await;
                tokio::task::yield_now().await;
            } else {
                return statuses;
            }
        }
    })
    .await
    {
        Ok(statuses) => statuses,
        Err(_) => {
            for (node_id, status) in st_interim.iter() {
                if *status != TestOutcome::Passed {
                    tracing::error!("Node {} had missing status: {:?}", node_id, status);
                }
            }

            panic!("Test timed out after 250ms")
        }
    };

    test.shutdown(test_handles).await;

    // Now verify all statuses are Passed
    assert!(
        final_statuses.values().all(|s| *s == TestOutcome::Passed),
        "Not all nodes passed. Final statuses: {:?}",
        final_statuses
    );
}
