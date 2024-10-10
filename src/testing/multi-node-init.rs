use crate::logging;

pub async fn init_nodes(num_nodes: u64) -> Vec<Sailfish> {
    logging::init_logging();

    let mut nodes = vec![];
    for i in 0..num_nodes {
        let (private_key, public_key) = generate_key_pair([0u8; 32], i);
        let sailfish = Sailfish::new(public_key, private_key, i);
        nodes.push(sailfish);
    }

    let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = nodes
        .iter()
        .map(|node| (node.peer_id.clone(), node.bind_address.clone()))
        .collect();

    for node in nodes {
        node.initialize_networking(bootstrap_nodes.clone(), vec![])
            .await;
    }

    nodes
}
