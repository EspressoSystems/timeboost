use timeboost_core::logging;

use crate::tests::consensus::helpers::{
    message_helper::MessageHelper,
    test_helpers::{create_keys, create_node_instruments},
};

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    let num_nodes = 5;

    let keys = create_keys(num_nodes);
    let helper = MessageHelper::new(&keys);
    let mut nodes = create_node_instruments(keys.clone());
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    let vertices_for_round = helper.add_vertices_to_node(3, node_handle);

    let input_msgs = helper.create_vertex_msgs(4, vertices_for_round);

    for msg in input_msgs {
        node_handle.handle_message(msg)
    }

    assert_eq!(node_handle.actions_taken.len(), 3);
}
