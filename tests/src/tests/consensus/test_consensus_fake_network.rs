use std::collections::{HashMap, HashSet};

use multisig::PublicKey;
use sailfish::types::{Evidence, RoundNumber};
use timeboost_utils::types::logging;
use timeboost_utils::unsafe_zero_keypair;

use crate::prelude::*;
use crate::tests::consensus::helpers::node_instrument::TestNodeInstrument;
use crate::tests::consensus::helpers::{
    fake_network::FakeNetwork, interceptor::Interceptor, test_helpers::make_consensus_nodes,
};

#[tokio::test]
async fn test_multi_round_consensus() {
    logging::init_logging();

    let num_nodes = 4;
    let (nodes, _manager) = make_consensus_nodes(num_nodes);

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
        assert_eq!(node_instrument.node().round(), round);
    }
}

#[tokio::test]
async fn test_timeout_round_and_no_vote() {
    logging::init_logging();
    let num_nodes = 4;
    let (nodes, manager) = make_consensus_nodes(num_nodes);

    let timeout_at_round = RoundNumber::new(2);

    let interceptor = Interceptor::new(
        move |msg: &Message, node_handle: &mut TestNodeInstrument| {
            if let Message::Vertex(v) = msg {
                if *v.data().round().data() == timeout_at_round
                    && *v.signing_key()
                        == manager
                            .committee()
                            .leader(**v.data().round().data() as usize)
                {
                    let timeout_msgs = manager.create_timeout_msgs(timeout_at_round.into());
                    node_handle.add_msgs(timeout_msgs);
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
        .all(|c| c.timeout_accumulators().count() == 0));

    // Process timeouts
    network.process();

    assert!(network
        .consensus()
        .any(|c| c.timeout_accumulators().count() > 0));

    // Process timeouts (create Timeout Certificate)
    network.process();

    assert!(network
        .consensus()
        .any(|c| c.timeout_accumulators().count() > 0));

    // Leader send vertex with no vote certificate and timeout certificate
    network.process();

    // After the NVC has been created, the no-vote accumulator is empty.
    assert!(network
        .leader(timeout_at_round)
        .no_vote_accumulators()
        .find(|(r, _)| r == &timeout_at_round)
        .is_none());

    let nodes_msgs = network.msgs_in_queue();

    // Ensure we have messages from all nodes
    assert_eq!(nodes_msgs.len(), usize::from(num_nodes));

    for (_id, msgs) in nodes_msgs {
        if let Some(Message::Vertex(vertex)) = msgs.front() {
            let data = vertex.data();

            // Assert that no_vote_cert and timeout_cert are present
            assert!(
                data.no_vote_cert().is_some(),
                "No vote certificate should be present."
            );
            assert!(
                data.evidence().is_timeout(),
                "Timeout certificate should be present."
            );

            // Ensure the vertex is from the leader
            let expected_leader = network.leader_for_round(*data.round().data());
            assert!(
                *vertex.signing_key() == expected_leader,
                "Vertex should be signed by the leader."
            );
        } else {
            panic!("Expected a vertex message, but got none or a different type.");
        }
    }

    network.process();

    // Everyone moved 2 rounds, so timeout accumulators should be empty again.
    assert!(network
        .consensus()
        .all(|c| c.timeout_accumulators().count() == 0));

    let mut i = 0;
    let current_round = network.current_round();
    while i < 50 {
        network.process();
        i += 1;
    }

    // verify progress can be made after timeout
    for node_instrument in network.nodes.values() {
        assert_eq!(node_instrument.node().round(), current_round + i);
    }
}

#[tokio::test]
async fn test_invalid_vertex_signatures() {
    logging::init_logging();

    let num_nodes = 5;
    let invalid_node_id = num_nodes + 1;

    let (nodes, manager) = make_consensus_nodes(num_nodes);

    let invalid_msg_at_round = RoundNumber::new(5);

    let interceptor = Interceptor::new(
        move |msg: &Message, _node_handle: &mut TestNodeInstrument| {
            if let Message::Vertex(_e) = msg {
                // generate keys for invalid node for a node one not in stake table
                let invalid_kpair = unsafe_zero_keypair(invalid_node_id);
                // modify current network message with this invalid one
                return vec![manager.create_vertex_proposal_msg(msg.round(), &invalid_kpair)];
            }
            // if not vertex leave msg alone
            vec![msg.clone()]
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
        assert_eq!(node_instrument.node().round(), invalid_msg_at_round);
    }
}

#[test]
fn basic_liveness() {
    logging::init_logging();

    let (mut nodes, _manager) = make_consensus_nodes(5);

    let mut actions: Vec<(PublicKey, Vec<Action>)> = nodes
        .iter_mut()
        .map(|(id, node_handle)| {
            let node = node_handle.node_mut();
            (
                *id,
                node.go(Dag::new(node.committee_size()), Evidence::Genesis),
            )
        })
        .collect();

    // Track what each node delivers as output:
    let mut delivered: HashMap<PublicKey, Vec<(RoundNumber, PublicKey)>> = HashMap::new();

    // Run for a couple of rounds:
    for _ in 0..17 {
        let mut next = Vec::new();
        for (id, aa) in &actions {
            for node_handle in &mut nodes.values_mut() {
                let n = node_handle.node_mut();
                for a in aa {
                    let na = match a {
                        Action::Deliver(data) => {
                            if n.public_key() == *id {
                                delivered
                                    .entry(*id)
                                    .or_default()
                                    .push((data.round(), data.source()));
                            }
                            continue;
                        }
                        Action::SendProposal(e) => n.handle_vertex(e.clone()),
                        Action::SendTimeout(e) => n.handle_timeout(e.clone()),
                        Action::SendTimeoutCert(x) => n.handle_timeout_cert(x.clone()),
                        Action::SendNoVote(to, e) if n.public_key() == *to => {
                            n.handle_no_vote(e.clone())
                        }
                        Action::SendNoVote(..) | Action::ResetTimer(..) => continue,
                    };
                    if !na.is_empty() {
                        next.push((n.public_key(), na))
                    }
                }
            }
        }
        for node_handle in nodes.values() {
            let n = node_handle.node();
            assert!(n.dag().depth() <= 7);
            if n.committed_round() > 2.into() {
                // The DAG should not contain data below committed round - 2:
                assert!(n.dag().max_round().unwrap() >= n.committed_round() - 2);
            }
            // No one is late => buffer should always be empty:
            assert_eq!(0, n.buffer_depth());
        }
        actions = next
    }

    for node_handle in nodes.values() {
        let n = node_handle.node();
        assert_eq!(n.committed_round(), 15.into())
    }

    // Every node should have delivered the same output:
    for (a, b) in delivered.values().zip(delivered.values().skip(1)) {
        assert!(!a.is_empty());
        assert_eq!(a, b)
    }

    // Integrity: a node should never deliver duplicate (round, key) values:
    let a = delivered.values().next().unwrap();
    let b = HashSet::<&(RoundNumber, PublicKey)>::from_iter(a);
    assert_eq!(a.len(), b.len());
}
