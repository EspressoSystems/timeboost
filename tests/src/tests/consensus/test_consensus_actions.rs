use timeboost_core::{
    logging,
    types::{
        message::{Action, Message},
        round_number::RoundNumber,
    },
};

use crate::tests::consensus::helpers::key_manager::KeyManager;

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    let num_nodes = 8;

    // Setup key manager and nodes
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    // Setup up consensus state
    let mut round = 7;
    let node = node_handle.node_mut();
    let (dag, vertices_for_round) = manager.prepare_dag(round, node.committee());
    node.go(dag);

    // Craft messages
    round += 1;
    let input_msgs = manager.create_vertex_msgs(round, vertices_for_round);

    // Process
    for msg in input_msgs {
        node_handle.handle_message(msg);
    }

    // Expectations
    assert_eq!(node_handle.actions_taken_len(), 2);

    let expected_round = RoundNumber::new(round + 1);
    let proposal = node_handle.expected_vertex_proposal_action(expected_round);
    let action_expectations = vec![Action::ResetTimer(expected_round), proposal];

    node_handle.assert_actions(action_expectations);
}

#[tokio::test]
async fn test_single_node_timeout() {
    logging::init_logging();

    let num_nodes = 5;

    // Setup key manager and nodes
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    // Setup up consensus state
    let mut round = 4;
    let node = node_handle.node_mut();
    let (dag, _vertices_for_round) = manager.prepare_dag(round, node.committee());
    node.go(dag);

    // Craft messages
    round += 1;
    let input_msgs = manager.create_timeout_msgs(round);

    // Process timeouts
    let mut expected_cert = None;
    for msg in input_msgs {
        node_handle.handle_message(msg.clone());
        let cert = node_handle.timeout_cert(msg.round());
        if cert.is_some() && expected_cert.is_none() {
            // Once we have enough votes store the certificate for expected cert
            // This is what we out put in the action and can change once we receive more the 2f + 1 signers
            expected_cert = cert;
        }
    }

    // Expectations
    assert_eq!(node_handle.actions_taken_len(), 2);

    let expected_round = RoundNumber::new(round);
    let timeout = node_handle.expected_timeout(expected_round);
    let send_cert = Action::SendTimeoutCert(expected_cert.unwrap());
    let action_expectations = vec![timeout, send_cert];

    node_handle.assert_actions(action_expectations);
    node_handle.assert_timeout_accumulator(expected_round, num_nodes);
}

#[tokio::test]
async fn test_single_node_timeout_cert() {
    logging::init_logging();

    let num_nodes = 6;

    // Setup key manager and nodes
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    // Setup up consensus state
    let mut round = 3;
    let node = node_handle.node_mut();
    let (dag, vertices_for_round) = manager.prepare_dag(round, node.committee());
    node.go(dag);

    // Craft messages, skip leader vertex
    round += 1;
    let mut input_msgs: Vec<Message> = manager
        .create_vertex_msgs(round, vertices_for_round)
        .iter()
        .filter(|m| {
            if let Message::Vertex(v) = m {
                let d = v.data();
                // Process non leader vertices
                *d.source() != node_handle.node().committee().leader(d.round())
            } else {
                panic!("Expected vertex message in test");
            }
        })
        .cloned()
        .collect();

    // Process non leader vertices
    for msg in input_msgs {
        node_handle.handle_message(msg);
    }

    // No actions taken since no leader vertex
    assert_eq!(node_handle.actions_taken_len(), 0);

    // craft timeouts
    input_msgs = manager.create_timeout_msgs(round);

    // Process timeouts
    let mut expected_cert = None;
    for msg in input_msgs {
        node_handle.handle_message(msg.clone());
        let cert = node_handle.timeout_cert(msg.round());
        if cert.is_some() && expected_cert.is_none() {
            // Once we have enough votes store the certificate for expected cert
            // This is what we out put in the action and can change once we receive more the 2f + 1 signers
            expected_cert = cert;
        }
    }

    // Verify timeout actions
    let expected_round = RoundNumber::new(round);
    let timeout = node_handle.expected_timeout(expected_round);
    let send_cert = Action::SendTimeoutCert(expected_cert.unwrap());

    node_handle.assert_actions(vec![timeout, send_cert]);
    node_handle.assert_timeout_accumulator(expected_round, num_nodes);
    node_handle.clear_actions();

    // Handle certificate msg (send no vote, advance round, reset timer, propose for r + 1)
    let cert = node_handle.timeout_cert(expected_round).unwrap();
    node_handle.handle_message(Message::TimeoutCert(cert));
    assert_eq!(node_handle.actions_taken_len(), 3);

    node_handle.assert_actions(vec![
        node_handle.expected_no_vote(expected_round), // No vote for round r to leader in r + 1
        Action::ResetTimer(expected_round + 1),       // Advance round reset timer
        node_handle.expected_vertex_proposal_action(expected_round + 1), // Vertex proposal for r + 1
    ]);

    // Advancing round, timeout accumulator should be cleared for round r
    node_handle.assert_timeout_accumulator(expected_round, 0);
}
