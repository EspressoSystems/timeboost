use timeboost_core::{
    logging,
    types::message::{Action, Message, Timeout},
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::tests::consensus::helpers::key_manager::KeyManager;

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    // Setup key manager and nodes
    let num_nodes = 8;
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");
    let committee = node_handle.committee().clone();

    // Setup expectations
    let expected_round = RoundNumber::new(9);
    let edges = manager.edges_for_round(expected_round, &committee, false);
    let vertex_proposal = node_handle.expected_vertex_proposal(expected_round, edges, None);
    node_handle.insert_expected_actions(vec![
        Action::ResetTimer(expected_round),
        Action::SendProposal(vertex_proposal),
    ]);

    // Setup up consensus state
    let mut round = 7;
    let node = node_handle.node_mut();
    let (dag, vertices_for_round) = manager.prepare_dag(round, &committee);
    node.go(dag);

    // Craft messages
    round += 1;
    let input_msgs = manager.create_vertex_msgs(round, vertices_for_round);

    // Process
    for msg in input_msgs {
        node_handle.handle_message_and_verify_actions(msg);
    }

    // Ensure we went through all expected actions
    assert!(
        node_handle.expected_actions_is_empty(),
        "Test is done but there are still remaining actions."
    );
}

#[tokio::test]
async fn test_single_node_timeout() {
    logging::init_logging();

    // Setup key manager and nodes
    let num_nodes = 5;
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");
    let committee = node_handle.committee().clone();

    // Setup expectations
    let expected_round = RoundNumber::new(5);
    let timeout = node_handle.expected_timeout(expected_round);
    let signers = manager.signers(Timeout::new(expected_round), committee.quorum_size().get());
    let send_cert = node_handle.expected_timeout_certificate(signers);
    node_handle.insert_expected_actions(vec![
        Action::SendTimeout(timeout),
        Action::SendTimeoutCert(send_cert),
    ]);

    // Setup up consensus state
    let mut round = 4;
    let node = node_handle.node_mut();
    let (dag, _vertices_for_round) = manager.prepare_dag(round, &committee);
    node.go(dag);

    // Craft messages
    round += 1;
    let input_msgs = manager.create_timeout_msgs(round);

    // Process timeouts
    for msg in input_msgs {
        node_handle.handle_message_and_verify_actions(msg);
    }

    // Ensure we went through all expected actions
    node_handle.assert_timeout_accumulator(expected_round, num_nodes);
    assert!(
        node_handle.expected_actions_is_empty(),
        "Test is done but there are still remaining actions."
    );
}

#[tokio::test]
async fn test_single_node_timeout_cert() {
    logging::init_logging();

    // Setup key manager and nodes
    let num_nodes = 5;
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");
    let committee = node_handle.committee().clone();

    // Setup expectations
    let expected_round = RoundNumber::new(4);
    let timeout = node_handle.expected_timeout(expected_round);
    let no_vote = node_handle.expected_no_vote(expected_round);

    // Signers and cert for 2f + 1 nodes
    let signers = manager.signers(Timeout::new(expected_round), committee.quorum_size().get());
    // The first cert is sent when we see 2f + 1 timeouts
    // We will still get other timeout votes causing cert to change
    let send_cert = node_handle.expected_timeout_certificate(signers);

    // Signers from all nodes and cert
    let signers = manager.signers(Timeout::new(expected_round), committee.size().get());
    // Proposal will send with a certificate with all signers
    let expected_cert = node_handle.expected_timeout_certificate(signers);
    let vertex_proposal = node_handle.expected_vertex_proposal(
        expected_round + 1,
        // Skip leader edge since we do below when craft vertex proposal messages
        manager.edges_for_round(expected_round, &committee, true),
        Some(expected_cert),
    );
    node_handle.insert_expected_actions(vec![
        Action::SendTimeout(timeout),
        Action::SendTimeoutCert(send_cert.clone()),
        Action::SendNoVote(committee.leader(*expected_round as usize + 1), no_vote),
        Action::ResetTimer(expected_round + 1),
        Action::SendProposal(vertex_proposal),
    ]);

    // Setup up consensus state
    let node = node_handle.node_mut();
    let (dag, vertices_for_round) = manager.prepare_dag(*expected_round - 1, &committee);
    node.go(dag);

    // Craft messages, skip leader vertex
    let mut input_msgs: Vec<Message> = manager
        .create_vertex_msgs(*expected_round, vertices_for_round)
        .iter()
        .filter(|m| {
            if let Message::Vertex(v) = m {
                let d = v.data();
                // Process non leader vertices
                *d.source() != committee.leader(*d.round() as usize)
            } else {
                panic!("Expected vertex message in test");
            }
        })
        .cloned()
        .collect();

    // Process non leader vertices
    for msg in input_msgs {
        node_handle.handle_message_and_verify_actions(msg);
    }

    // Craft timeouts
    input_msgs = manager.create_timeout_msgs(*expected_round);

    // Process timeouts
    for msg in input_msgs {
        node_handle.handle_message_and_verify_actions(msg);
    }

    node_handle.assert_timeout_accumulator(expected_round, num_nodes);

    // Handle certificate msg (send no vote, advance round, reset timer, propose for r + 1)
    node_handle.handle_message_and_verify_actions(Message::TimeoutCert(send_cert));

    // Ensure we went through all expected actions
    node_handle.assert_timeout_accumulator(expected_round, 0);
    assert!(
        node_handle.expected_actions_is_empty(),
        "Test is done but there are still remaining actions."
    );
}
