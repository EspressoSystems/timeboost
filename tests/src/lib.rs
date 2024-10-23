use std::sync::Arc;

use async_lock::RwLock;
use hotshot_types::{PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use multiaddr::multiaddr;
use sailfish::{
    consensus::{committee::StaticCommittee, Consensus},
    logging,
    sailfish::{generate_key_pair, Sailfish},
    types::{NodeId, PublicKey},
};

pub mod net;

#[cfg(test)]
mod tests;

const SEED: [u8; 32] = [0u8; 32];

pub fn make_consensus_nodes(num_nodes: u64) -> Vec<(NodeId, Consensus)> {
    let keys = (0..num_nodes)
        .map(|i| generate_key_pair(SEED, i))
        .collect::<Vec<_>>();
    let committee = StaticCommittee::new(keys.iter().map(|(_, k)| k).cloned().collect());
    keys.into_iter()
        .enumerate()
        .map(|(i, (sk, pk))| {
            (
                NodeId::from(i as u64),
                Consensus::new(pk, sk, committee.clone()),
            )
        })
        .collect()
}

pub struct Group {
    pub fish: Vec<Sailfish>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<PublicKey>>>,
}

impl Group {
    pub fn new(size: u16) -> Self {
        logging::init_logging();

        let mut nodes = vec![];
        let mut vcgfs = vec![];

        for i in 0..size {
            let cfg = ValidatorConfig::generated_from_seed_indexed(SEED, i as u64, 1, false);
            let (sk, pk) = generate_key_pair(SEED, i as u64);
            let sailfish = Sailfish::new(
                i as u64,
                pk,
                sk,
                multiaddr!(Ip4([0, 0, 0, 0]), Tcp(8000 + i)),
            )
            .unwrap();
            nodes.push(sailfish);
            vcgfs.push(cfg)
        }

        let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = nodes
            .iter()
            .map(|node| (*node.peer_id(), node.bind_addr().clone()))
            .collect();

        let staked_nodes: Vec<PeerConfig<PublicKey>> =
            vcgfs.iter().map(|c| c.public_config()).collect();

        let bootstrap_nodes = Arc::new(RwLock::new(bootstrap_nodes));
        let staked_nodes = Arc::new(staked_nodes);

        Self {
            fish: nodes,
            bootstrap_nodes,
            staked_nodes,
        }
    }
}
