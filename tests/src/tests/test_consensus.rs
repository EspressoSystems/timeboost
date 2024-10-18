use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{
    consensus::Consensus,
    types::{certificate::make_genesis_vertex_certificate, message::SailfishEvent},
};

use crate::make_consensus_nodes;

async fn broadcast_event(event: SailfishEvent, nodes: &mut Vec<Consensus>) -> Vec<SailfishEvent> {
    let mut events = vec![];
    for node in nodes.iter_mut() {
        match node.handle_event(event.clone()).await {
            Ok(output_events) => events.extend(output_events),
            Err(e) => tracing::error!("Error: {}", e),
        }
    }
    events
}

async fn broadcast_genesis_certificate(nodes: &mut Vec<Consensus>) {
    let certificates = nodes
        .iter()
        .map(|n| make_genesis_vertex_certificate(n.context.public_key))
        .collect::<Vec<_>>();

    // Multicast all certs to all nodes
    for certificate in certificates {
        broadcast_event(SailfishEvent::VertexCertificateSend(certificate), nodes).await;
    }
}

#[tokio::test]
async fn test_vertex_certificate_formation() {
    let target_node = 0;

    // Used for the threshold.
    let mut nodes = make_consensus_nodes(5);

    // Broadcast the genesis certificate to all nodes.
    broadcast_genesis_certificate(&mut nodes).await;

    // Now, focusing on node 0, we should see it receive 2f + 1 certificates for the genesis round.
    let node = &mut nodes[target_node];
    let certificates = node
        .vertex_certificates
        .get(&ViewNumber::genesis())
        .unwrap();
    assert_eq!(certificates.len(), 2);
}

#[tokio::test]
async fn test_multi_roound_consensus() {
    let consensus_instances = make_consensus_nodes(3);

    let round = ViewNumber::genesis();
    loop {
        if *round == 10 {
            break;
        }
    }
}
