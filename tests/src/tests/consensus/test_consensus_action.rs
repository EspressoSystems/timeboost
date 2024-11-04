use timeboost_core::{
    logging,
    types::{message::Action, round_number::RoundNumber},
};

use crate::tests::consensus::helpers::key_manager::KeyManager;

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    let num_nodes = 5;

    // Setup
    let manager = KeyManager::new(num_nodes);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    let mut round = 3;
    let vertices_for_round = manager.add_vertices_to_node(round, node_handle);

    round += 1;
    let input_msgs = manager.create_vertex_msgs(round, vertices_for_round);

    for msg in input_msgs {
        node_handle.handle_message(msg);
    }

    // Expectations
    assert_eq!(node_handle.actions_taken_len(), 2);

    let expected_round = RoundNumber::new(round + 1);
    let proposal = node_handle.create_vertex_action(expected_round);
    let action_expectations = vec![Action::ResetTimer(expected_round), proposal];

    node_handle.assert_actions(action_expectations);
}
