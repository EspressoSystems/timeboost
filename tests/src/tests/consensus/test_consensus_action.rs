use timeboost_core::{
    logging,
    types::{envelope::Envelope, message::Message},
};

use crate::tests::consensus::helpers::test_helpers::{
    create_keys, create_node_instruments, create_vertex,
};

#[tokio::test]
async fn test_single_node_advance() {
    logging::init_logging();

    let num_nodes = 5;

    let keys = create_keys(num_nodes);
    let mut nodes = create_node_instruments(keys.clone());
    let node_handle = nodes.first_mut().expect("Node 0 should be present");

    let mut vertices = Vec::new();
    for (_, pub_key) in keys.clone() {
        let v = create_vertex(3, pub_key);
        vertices.push(*v.id());
        node_handle.add_vertex_to_dag(v);
    }

    let mut input_msgs = Vec::new();
    for (private_key, pub_key) in keys.clone() {
        let mut v = create_vertex(4, pub_key);
        v.add_strong_edges(vertices.clone());

        let e = Envelope::signed(v, &private_key, pub_key);

        input_msgs.push(Message::Vertex(e.cast()));
    }

    for msg in input_msgs {
        node_handle.handle_message(msg)
    }

    assert_eq!(node_handle.actions_taken.len(), 3);
}
