use std::sync::Arc;

use async_lock::RwLock;
use hotshot_types::{PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use multiaddr::multiaddr;
use sailfish::sailfish::Sailfish;
use timeboost_core::types::{Keypair, PublicKey};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;

pub struct Group {
    pub fish: Vec<Sailfish>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<PublicKey>>>,
}

impl Group {
    pub fn new(size: u16) -> Self {
        let mut nodes = vec![];
        let mut vcgfs = vec![];

        for i in 0..size {
            let cfg = ValidatorConfig::generated_from_seed_indexed(
                Keypair::ZERO_SEED,
                i as u64,
                1,
                false,
            );
            let kpr = Keypair::zero(i as u64);
            let sailfish =
                Sailfish::new(i as u64, kpr, multiaddr!(Ip4([0, 0, 0, 0]), Tcp(8000 + i))).unwrap();
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
