use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::committee::StaticCommittee,
    sailfish::generate_key_pair,
    types::{message::Message, Signature},
};
use timeboost_core::logging;

use crate::{
    tests::consensus::helpers::{
        fake_network::FakeNetwork,
        interceptor::Interceptor,
        test_helpers::{
            create_timeout_certificate_msg, create_vertex_proposal_msg, create_vote,
            make_consensus_nodes,
        },
    },
    SEED,
};
use bitvec::{bitvec, vec::BitVec};

#[tokio::test]
async fn test_timeout_round_and_note_vote() {
    logging::init_logging();
    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes, None);

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

    let nodes_msgs = network.msgs_in_queue();

    // Ensure we have messages from all nodes
    assert_eq!(nodes_msgs.len() as u64, num_nodes);

    for (_id, msgs) in nodes_msgs {
        if let Some(Message::Vertex(vertex)) = msgs.front() {
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
            let expected_leader = network.leader_for_round(data.round());
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

    let mut network = FakeNetwork::new(nodes, None);
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

#[tokio::test]
async fn test_invalid_vertex_signatures() {
    logging::init_logging();

    let num_nodes = 5;
    let invalid_node_id = num_nodes + 1;

    let nodes = make_consensus_nodes(num_nodes);

    let invalid_msg_at_round = ViewNumber::new(5);

    let interceptor = Interceptor::new(
        Box::new(move |msg: &Message, _committee: &StaticCommittee| {
            if let Message::Vertex(_e) = msg {
                // generate keys for invalid node for a node one not in stake table
                let new_keys = generate_key_pair(SEED, invalid_node_id);
                // modify current network message with this invalid one
                vec![create_vertex_proposal_msg(
                    msg.round(),
                    new_keys.1,
                    &new_keys.0,
                )]
            } else {
                // if not vertex leave msg alone
                vec![msg.clone()]
            }
        }),
        invalid_msg_at_round,
    );

    let mut network = FakeNetwork::new(nodes, Some(interceptor));
    network.start();
    network.process();

    // Spin the test for some rounds, progress should stop at `invalid_msg_at_round`
    // but go for some extra cycles
    let mut i = 0;
    while i < *invalid_msg_at_round + 5 {
        network.process();
        i += 1;
    }

    // verify no progress was made
    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(node.round(), invalid_msg_at_round);
    }
}

#[tokio::test]
async fn test_invalid_timeout_certificate() {
    logging::init_logging();

    let num_nodes = 4;
    let invalid_node_id = num_nodes + 1;

    let nodes = make_consensus_nodes(num_nodes);

    let invalid_msg_at_round = ViewNumber::new(3);

    let interceptor = Interceptor::new(
        Box::new(move |msg: &Message, committee: &StaticCommittee| {
            if let Message::Vertex(e) = msg {
                // Generate keys for invalid node for a nodes that are not in stake table
                // And create a certificate from this
                let mut signers: (BitVec, Vec<Signature>) =
                    (bitvec![0; num_nodes as usize], Vec::new());
                let mut timeout = None;
                for i in 0..num_nodes {
                    let fake_node_id = i + invalid_node_id;
                    let new_keys = generate_key_pair(SEED, fake_node_id);
                    timeout = Some(create_vote(e.data().round(), new_keys.1, &new_keys.0));
                    signers.0.set(i as usize, true);
                    signers.1.push(timeout.clone().unwrap().signature().clone());
                }

                // process current message and the invalid certificate
                // We should discard the message with the invalid certificate in consensus
                // And never broadcast a vertex with a timeout certificate
                vec![
                    msg.clone(),
                    create_timeout_certificate_msg(timeout.unwrap(), &signers, committee),
                ]
            } else {
                // if not vertex leave msg alone
                vec![msg.clone()]
            }
        }),
        invalid_msg_at_round,
    );

    let mut network = FakeNetwork::new(nodes, Some(interceptor));
    network.start();

    // Spin the test for some rounds
    let mut i = 0;
    let rounds = 7;
    while i < 7 {
        network.process();
        for (_id, msgs) in network.msgs_in_queue() {
            for msg in msgs {
                if let Message::Vertex(vertex) = msg {
                    assert!(
                        vertex.data().timeout_cert().is_none(),
                        "We should never receive a vertex with a timeout certificate"
                    );
                }
            }
        }

        i += 1;
    }

    // verify no progress was made
    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(*node.round(), rounds);
    }
}
