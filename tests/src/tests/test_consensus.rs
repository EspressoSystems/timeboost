use std::collections::{HashMap, VecDeque};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::{Consensus, Dag},
    logging,
    types::{
        message::{Action, Message},
        NodeId, PublicKey,
    },
};
use tracing::info;

use crate::make_consensus_nodes;

struct FakeNetwork {
    nodes: HashMap<NodeId, (Consensus, VecDeque<Message>)>,
}

impl FakeNetwork {
    fn new(nodes: Vec<(NodeId, Consensus)>) -> Self {
        Self {
            nodes: nodes
                .into_iter()
                .map(|(id, n)| (id, (n, VecDeque::new())))
                .collect(),
        }
    }

    fn start(&mut self) {
        let mut next = Vec::new();
        for (node, _) in self.nodes.values_mut() {
            for a in node.go(Dag::new()) {
                Self::handle_action(a, &mut next)
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
                (Some(p), m) => {
                    let (_, q) = self
                        .nodes
                        .values_mut()
                        .find(|(n, _)| n.public_key() == &p)
                        .unwrap();
                    q.push_back(m);
                }
            }
        }
    }

    fn process(&mut self) {
        let mut next = Vec::new();
        for (node, queue) in self.nodes.values_mut() {
            while let Some(m) = queue.pop_front() {
                for a in node.handle_message(m) {
                    Self::handle_action(a, &mut next)
                }
            }
        }
        self.dispatch(next);
    }

    fn handle_action(a: Action, msgs: &mut Vec<(Option<PublicKey>, Message)>) {
        let m = match a {
            Action::ResetTimer(_) => {
                // TODO
                info!("reset timer");
                return;
            }
            Action::Deliver(_b, r, src) => {
                // TODO
                info!(%r, %src, "deliver");
                return;
            }
            Action::SendNoVote(to, e) => (Some(to), Message::NoVote(e.cast())),
            Action::SendProposal(e) => (None, Message::Vertex(e.cast())),
            Action::SendTimeout(e) => (None, Message::Timeout(e.cast())),
            Action::SendTimeoutCert(c) => (None, Message::TimeoutCert(c)),
        };
        msgs.push(m)
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
