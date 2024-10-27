use std::collections::{HashMap, VecDeque};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::{Consensus, Dag},
    logging,
    types::{
        envelope::Envelope,
        message::{Action, Message, Timeout},
        NodeId, PublicKey,
    },
};
use tracing::info;

use crate::make_consensus_nodes;

struct FakeNetwork {
    nodes: HashMap<PublicKey, (Consensus, VecDeque<Message>)>,
}

impl FakeNetwork {
    fn new(nodes: Vec<(PublicKey, Consensus)>) -> Self {
        Self {
            nodes: nodes
                .into_iter()
                .map(|(id, n)| (id, (n, VecDeque::new())))
                .collect(),
        }
    }

    fn start(&mut self) {
        let mut next = Vec::new();
        for (_pub_key, (node, _)) in self.nodes.iter_mut() {
            for a in node.go(Dag::new()) {
                Self::handle_action(node.id(), a, &mut next)
            }
        }
        self.dispatch(next)
    }

    fn current_round(&self) -> ViewNumber {
        self.nodes
            .values()
            .map(|(node, _)| node.round())
            .max()
            .unwrap()
    }

    fn dispatch(&mut self, msgs: Vec<(Option<PublicKey>, Message)>) {
        for m in msgs {
            match m {
                (None, msg) => {
                    for (_, queue) in self.nodes.values_mut() {
                        queue.push_back(msg.clone());
                    }
                }
                (Some(pub_key), msg) => {
                    let (_, queue) = self.nodes.get_mut(&pub_key).unwrap();
                    queue.push_back(msg);
                }
            }
        }
    }

    fn process(&mut self) {
        let mut next_msgs = Vec::new();
        for (_pub_key, (node, queue)) in self.nodes.iter_mut() {
            while let Some(msg) = queue.pop_front() {
                for a in node.handle_message(msg) {
                    Self::handle_action(node.id(), a, &mut next_msgs)
                }
            }
        }
        self.dispatch(next_msgs);
    }

    fn handle_action(node: NodeId, a: Action, msgs: &mut Vec<(Option<PublicKey>, Message)>) {
        let msg = match a {
            Action::ResetTimer(_) => {
                // TODO
                info!(%node, "reset timer");
                return;
            }
            Action::Deliver(_b, r, src) => {
                // TODO
                info!(%node, %r, %src, "deliver");
                return;
            }
            Action::SendNoVote(to, e) => (Some(to), Message::NoVote(e.cast())),
            Action::SendProposal(e) => (None, Message::Vertex(e.cast())),
            Action::SendTimeout(e) => (None, Message::Timeout(e.cast())),
            Action::SendTimeoutCert(c) => (None, Message::TimeoutCert(c)),
        };
        msgs.push(msg)
    }

    fn mock_timeouts(&mut self, round: ViewNumber) {
        let mut msgs: Vec<(Option<PublicKey>, Message)> = Vec::new();
        for (node, queue) in self.nodes.values_mut() {
            // clear queue
            queue.clear();
            let data = Timeout::new(round);
            let e = Envelope::signed(data, node.private_key(), node.public_key().clone());
            let action = Action::SendTimeout(e);

            Self::handle_action(node.id(), action, &mut msgs);
        }
        self.dispatch(msgs);
    }

    fn get_msgs_in_queue(&self) -> HashMap<NodeId, VecDeque<Message>> {
        let nodes_msgs = self
            .nodes
            .values()
            .map(|node| (node.0.id(), node.1.clone()))
            .collect();
        nodes_msgs
    }
}

#[tokio::test]
async fn test_timeout_round_and_note_vote() {
    logging::init_logging();
    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes);

    network.start();

    // process 2 rounds
    network.process();
    network.process();

    // mock timeout
    let round = ViewNumber::new(2);
    network.mock_timeouts(round);

    // process timeout (create TC)
    network.process();

    // process no vote (send NVC)
    network.process();

    // leader send vertex no vote (accumulate NVC and propose vertex)
    network.process();

    let nodes_msgs = network.get_msgs_in_queue();

    // ensure we have messages from all nodes
    assert_eq!(nodes_msgs.len() as u64, num_nodes);

    for (_id, msgs) in nodes_msgs {
        // the next msg to be processed should be only 1
        assert_eq!(msgs.len(), 1);

        let msg = msgs.get(0);
        assert!(msg.is_some());

        match msg.unwrap() {
            Message::Vertex(vertex) => {
                // next message should be a vertex proposal with the no vote cert from leader
                assert!(vertex.data().no_vote_cert().is_some());
            }
            _ => assert!(false),
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
