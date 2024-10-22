use std::collections::{HashMap, VecDeque};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::Consensus,
    logging,
    types::{certificate::VertexCertificate, message::SailfishEvent},
};

use crate::make_consensus_nodes;

struct FakeNetwork {
    nodes: HashMap<u64, (Consensus, VecDeque<SailfishEvent>)>,
}

impl FakeNetwork {
    fn new(nodes: Vec<Consensus>) -> Self {
        Self {
            nodes: nodes
                .into_iter()
                .map(|n| (n.context.id, (n, VecDeque::new())))
                .collect(),
        }
    }

    fn current_round(&self) -> ViewNumber {
        self.nodes
            .values()
            .map(|(node, _)| node.round)
            .max()
            .unwrap()
    }

    fn genesis(&mut self) {
        let certs = self
            .nodes
            .iter()
            .map(|(_, (node, _))| {
                SailfishEvent::VertexCertificateRecv(VertexCertificate::genesis(
                    node.context.public_key,
                ))
            })
            .collect();

        self.broadcast_events(certs);
    }

    fn broadcast_events(&mut self, events: Vec<SailfishEvent>) {
        for (_, (_, queue)) in self.nodes.iter_mut() {
            queue.extend(events.clone());
        }
    }

    async fn process_events(&mut self) {
        let mut new_events = Vec::new();
        for (_, (node, queue)) in self.nodes.iter_mut() {
            while let Some(event) = queue.pop_front() {
                let in_event = event.transform_send_to_recv();
                let next_events = node.on_message(in_event).await.unwrap();
                new_events.extend(next_events);
            }
        }

        // Broadcast the new events. This lets us proceed in "rounds" of behavior.
        self.broadcast_events(new_events);
    }
}

#[tokio::test]
async fn test_vertex_certificate_formation() {
    logging::init_logging();

    let num_nodes = 3;

    // Used for the threshold.
    let nodes = make_consensus_nodes(num_nodes);
    let mut network = FakeNetwork::new(nodes);

    network.genesis();
    network.process_events().await;

    // Make sure that each node has received the genesis certificates.
    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(
            node.vertex_certificates
                .get(&ViewNumber::genesis())
                .unwrap()
                .len(),
            3
        );
    }
}

#[tokio::test]
async fn test_multi_round_consensus() {
    logging::init_logging();

    let num_nodes = 4;
    let nodes = make_consensus_nodes(num_nodes);

    let mut network = FakeNetwork::new(nodes);

    network.genesis();
    network.process_events().await;

    let mut round = ViewNumber::genesis();

    // Spin the test for one second.
    let timeout_result = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        while *round < 10 {
            network.process_events().await;
            round = network.current_round();
            tokio::task::yield_now().await;
        }
    })
    .await;

    assert!(timeout_result.is_ok());
    for (_, (node, _)) in network.nodes.iter() {
        assert_eq!(node.round, round);
    }
}
