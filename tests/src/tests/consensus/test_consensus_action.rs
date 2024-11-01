use timeboost_core::logging;

use crate::tests::consensus::helpers::{key_manager::KeyManager, test_helpers::create_keys};

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    let num_nodes = 5;

    let keys = create_keys(num_nodes);
    let manager = KeyManager::new(&keys);
    let mut nodes = manager.create_node_instruments();
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    let mut round = 3;
    let vertices_for_round = manager.add_vertices_to_node(round, node_handle);

    round += 1;
    let input_msgs = manager.create_vertex_msgs(round, vertices_for_round);

    for msg in input_msgs {
        node_handle.handle_message(msg)
    }

    assert_eq!(node_handle.actions_taken.len(), 3);
}
