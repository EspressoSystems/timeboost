use std::collections::{HashMap, VecDeque};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::{Consensus, Dag},
    logging,
    types::{
        message::{Action, Message},
        NodeId,
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
        self.broadcast(next)
    }

    fn current_round(&self) -> ViewNumber {
        self.nodes
            .values()
            .map(|(node, _)| node.round())
            .max()
            .unwrap()
    }

    fn broadcast(&mut self, msgs: Vec<Message>) {
        for (_, (_, queue)) in self.nodes.iter_mut() {
            queue.extend(msgs.clone());
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
        self.broadcast(next);
    }

    fn handle_action(a: Action, msgs: &mut Vec<Message>) {
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
            Action::SendNoVote(..) => {
                // TODO
                info!("unicast");
                return;
            }
            Action::SendProposal(e) => Message::Vertex(e.cast()),
            Action::SendTimeout(e) => Message::Timeout(e.cast()),
            Action::SendTimeoutCert(c) => Message::TimeoutCert(c),
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
    for _ in 0..3 {
        // while *round < 10 {
        network.process();
        round = network.current_round();
    }

    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(node.round(), round);
    }
}
