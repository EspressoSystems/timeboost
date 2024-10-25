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
                (None, m) => {
                    for (_, queue) in self.nodes.values_mut() {
                        queue.push_back(m.clone());
                    }
                }
                (Some(pub_key), m) => {
                    let (_, queue) = self.nodes.get_mut(&pub_key).unwrap();
                    queue.push_back(m);
                }
            }
        }
    }

    fn process(&mut self) {
        let mut next = Vec::new();
        for (_pub_key, (node, queue)) in self.nodes.iter_mut() {
            while let Some(m) = queue.pop_front() {
                for a in node.handle_message(m) {
                    Self::handle_action(node.id(), a, &mut next)
                }
            }
        }
        self.dispatch(next);
    }

    fn handle_action(node: NodeId, a: Action, msgs: &mut Vec<(Option<PublicKey>, Message)>) {
        let m = match a {
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
        msgs.push(m)
    }

    // TODO: clean up
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

    // TODO: clean up
    fn verify_outputs(&mut self) -> bool {
        for (_node, queue) in self.nodes.values() {
            if queue.len() != 1 {
                return false;
            }

            let Some(msg) = queue.get(0) else {
                return false;
            };

            match msg {
                Message::Vertex(v) => {
                    if v.data().no_vote_cert().is_none() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        return true;
    }
}

#[tokio::test]
async fn test_timeout() {
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
    assert!(network.verify_outputs());
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
