use std::collections::VecDeque;

use sailfish::consensus::Consensus;
use sailfish::sailfish::generate_key_pair;
use timeboost_core::logging;
use timeboost_core::types::Signature;
use timeboost_core::types::{message::Message, round_number::RoundNumber};

use crate::tests::consensus::helpers::test_helpers::{
    create_nodes, create_timeout_vote, create_timeout_vote_msg,
};
use crate::{
    tests::consensus::helpers::{
        fake_network::FakeNetwork,
        interceptor::Interceptor,
        test_helpers::{create_timeout_certificate_msg, create_vertex_proposal_msg},
    },
    SEED,
};
use bitvec::{bitvec, vec::BitVec};

#[tokio::test]
async fn test_multi_round_consensus() {
    logging::init_logging();

    let num_nodes = 4;
    let nodes = create_nodes(num_nodes, 0);

    let mut network = FakeNetwork::new(nodes, Interceptor::default());
    network.start();
    network.process();

    let mut round = RoundNumber::genesis();

    // Spin the test for some rounds.
    while *round < 10 {
        network.process();
        round = network.current_round();
    }

    for node_instrument in network.nodes.values() {
        assert_eq!(node_instrument.node.round(), round);
    }
}

#[tokio::test]
async fn test_timeout_round_and_no_vote() {
    logging::init_logging();
    let num_nodes = 4;
    let nodes = create_nodes(num_nodes, 0);

    let timeout_at_round = RoundNumber::new(2);

    let interceptor = Interceptor::new(
        move |msg: &Message, node: &mut Consensus, queue: &mut VecDeque<Message>| {
            if let Message::Vertex(v) = msg {
                if v.data().round() == timeout_at_round
                    && *v.signing_key() == node.committee().leader(v.data().round())
                {
                    for i in 0..num_nodes {
                        let keys = generate_key_pair(SEED, i);
                        let msg = create_timeout_vote_msg(msg.round(), keys.1, &keys.0);
                        queue.push_back(msg);
                    }
                    return vec![];
                }
            }
            vec![msg.clone()]
        },
        timeout_at_round,
    );

    let mut network = FakeNetwork::new(nodes, interceptor);

    network.start();

    // Process 2 rounds
    network.process();
    network.process();

    // No timeout messages expected:
    assert!(network
        .consensus()
        .all(|c| c.timeout_accumulators().is_empty()));

    // Process timeouts
    network.process();

    // Process timeout (create TC)
    network.process();

    // Some nodes should have received timeout messages.
    assert!(network
        .consensus()
        .any(|c| !c.timeout_accumulators().is_empty()));

    // Leader send vertex with no vote certificate and timeout certificate
    network.process();

    // After the NVC has been created, the no-vote accumulator is empty.
    assert!(
        network
            .leader(timeout_at_round)
            .no_vote_accumulator()
            .votes()
            == 0
    );

    // Everyone moved to the next round, so timeout accumulators should be empty again.
    assert!(network
        .consensus()
        .all(|c| c.timeout_accumulators().is_empty()));

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
async fn test_invalid_vertex_signatures() {
    logging::init_logging();

    let num_nodes = 5;
    let invalid_node_id = num_nodes + 1;

    let nodes = create_nodes(num_nodes, 0);

    let invalid_msg_at_round = RoundNumber::new(5);

    let interceptor = Interceptor::new(
        move |msg: &Message, _node: &mut Consensus, _queue: &mut VecDeque<Message>| {
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
        },
        invalid_msg_at_round,
    );

    let mut network = FakeNetwork::new(nodes, interceptor);
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
    for node_instrument in network.nodes.values() {
        assert_eq!(node_instrument.node.round(), invalid_msg_at_round);
    }
}

#[tokio::test]
async fn test_invalid_timeout_certificate() {
    logging::init_logging();

    let num_nodes = 4;
    let invalid_node_id = num_nodes + 1;

    let nodes = create_nodes(num_nodes, 0);

    let invalid_msg_at_round = RoundNumber::new(3);

    let interceptor = Interceptor::new(
        move |msg: &Message, node: &mut Consensus, queue: &mut VecDeque<Message>| {
            if let Message::Vertex(e) = msg {
                // Generate keys for invalid nodes (nodes that are not in stake table)
                // And create a timeout certificate from them
                let mut signers: (BitVec, Vec<Signature>) =
                    (bitvec![0; num_nodes as usize], Vec::new());
                let mut timeout = None;
                for i in 0..num_nodes {
                    let fake_node_id = i + invalid_node_id;
                    let new_keys = generate_key_pair(SEED, fake_node_id);
                    timeout = Some(create_timeout_vote(
                        e.data().round(),
                        new_keys.1,
                        &new_keys.0,
                    ));
                    signers.0.set(i as usize, true);
                    signers.1.push(timeout.clone().unwrap().signature().clone());
                }

                // Process current message this should be the leader vertex and the invalid certificate
                // We should discard the message with the invalid certificate in `handle_timeout_cert` since the signers are invalid
                // And never broadcast a vertex with a timeout certificate and send a no vote message
                // End of queue should be leader vertex inject process the certificate first
                if queue.is_empty() {
                    return vec![
                        create_timeout_certificate_msg(
                            timeout.unwrap(),
                            &signers,
                            node.committee(),
                        ),
                        msg.clone(),
                    ];
                }
                // Process leader vertex last, to test the certificate injection fails (we have 2f + 1 vertices for round r but no leader vertex yet)
                if *e.signing_key() == node.committee().leader(e.data().round()) {
                    queue.push_back(msg.clone());
                    return vec![];
                }
            }

            // Everthing else handle as normal
            vec![msg.clone()]
        },
        invalid_msg_at_round,
    );

    let mut network = FakeNetwork::new(nodes, interceptor);
    network.start();

    // Spin the test for some rounds
    let mut i = 0;
    let rounds = 7;
    while i < 7 {
        network.process();
        for (_id, msgs) in network.msgs_in_queue() {
            for msg in msgs {
                match msg {
                    Message::Vertex(v) => {
                        assert!(
                            v.data().timeout_cert().is_none(),
                            "We should never have a timeout cert in a message"
                        );
                    }
                    Message::NoVote(_nv) => {
                        panic!("We should never process a no vote message");
                    }
                    _ => {}
                }
            }
        }

        i += 1;
    }

    // verify progress was made
    for node_instrument in network.nodes.values() {
        assert_eq!(*node_instrument.node.round(), rounds);
    }
}
