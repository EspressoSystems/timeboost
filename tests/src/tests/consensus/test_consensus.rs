use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{logging, types::message::Message};

use crate::tests::consensus::helpers::{
    fake_network::FakeNetwork, test_helpers::make_consensus_nodes,
};

#[tokio::test]
async fn test_timeout_round_and_note_vote() {
    logging::init_logging();
    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes);

    network.start();

    // Process 2 rounds
    network.process();
    network.process();

    // Process a round without proposal from leader
    let round = ViewNumber::new(2);
    network.timeout_round(round);

    // Process timeout (create TC)
    network.process();

    // Process no vote msgs
    network.process();

    // Leader send vertex with no vote certificate and timeout certificate
    network.process();

    let nodes_msgs = network.get_msgs_in_queue();

    // Ensure we have messages from all nodes
    assert_eq!(nodes_msgs.len() as u64, num_nodes);

    for (_id, msgs) in nodes_msgs {
        // The next msg to be processed should be only 1
        assert_eq!(msgs.len(), 1);

        if let Some(Message::Vertex(vertex)) = msgs.get(0) {
            let data = vertex.data();

            // Assert that no_vote_cert and timeout_cert are present
            assert!(
                data.no_vote_cert().is_some(),
                "No vote certificate should be present."
            );
            assert!(
                data.timeout_cert().is_some(),
                "Timeout certificate should be present."
            );

            // Ensure the vertex is from the leader
            let expected_leader = network.get_leader_for_round(data.round());
            assert!(
                *vertex.signing_key() == expected_leader,
                "Vertex should be signed by the leader."
            );
        } else {
            panic!("Expected a vertex message, but got none or a different type.");
        }
    }
}

#[tokio::test]
async fn test_multi_round_consensus() {
    logging::init_logging();

    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes);
    network.start();
    network.process();

    let mut round = ViewNumber::genesis();

    // Spin the test for some rounds.
    while *round < 10 {
        network.process();
        round = network.current_round();
    }

    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(node.round(), round);
    }
}
