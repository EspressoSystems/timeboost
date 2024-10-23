use std::collections::{HashMap, VecDeque};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::Consensus, logging, types::{message::{Action, Message}, NodeId}
};

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

    async fn process(&mut self) {
        let mut next = Vec::new();
        for (_, (node, queue)) in self.nodes.iter_mut() {
            while let Some(m) = queue.pop_front() {
                for a in node.handle_message(m).await.unwrap() {
                    let m = match a {
                        Action::ResetTimer(_) => todo!("reset timer"),
                        Action::SendProposal(e) => Message::Vertex(e),
                        Action::SendTimeout(e) => Message::Timeout(e),
                        Action::SendTimeoutCert(c) => Message::TimeoutCert(c),
                        Action::SendNoVote(..) => todo!("unicast")
                    };
                    next.push(m)
                }
            }
        }
        self.broadcast(next);
    }
}

// TODO: actually make progress
#[tokio::test]
async fn test_multi_round_consensus() {
    logging::init_logging();

    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes);
    network.process().await;

    let mut round = ViewNumber::genesis();

    // Spin the test for one second.
    let _ = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        while *round < 10 {
            network.process().await;
            round = network.current_round();
            tokio::task::yield_now().await;
        }
    })
    .await;

    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(node.round(), round);
    }
}
