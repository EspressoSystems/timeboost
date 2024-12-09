use std::sync::Arc;

use async_lock::RwLock;
use libp2p_identity::PeerId;
use multiaddr::{multiaddr, Multiaddr};
use multisig::{Committee, Keypair, PublicKey};
use sailfish::sailfish::Sailfish;
use timeboost_utils::{unsafe_zero_keypair, PeerConfig, ValidatorConfig};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rbc;

pub struct Group {
    pub fish: Vec<Sailfish>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<PublicKey>>>,
    pub committee: Committee,
    pub keypairs: Vec<Keypair>,
}

impl Group {
    pub fn new(size: u16) -> Self {
        let mut nodes = vec![];
        let mut vcgfs = vec![];
        let mut pubks = vec![];

        let keyps: Vec<Keypair> = (0..size as u64).map(unsafe_zero_keypair).collect();

        for (i, kpr) in keyps.iter().enumerate() {
            let cfg = ValidatorConfig::generated_from_seed_indexed([0; 32], i as u64, 1, false);
            pubks.push((i as u8, kpr.public_key()));
            let sailfish = Sailfish::new(
                i as u64,
                kpr.clone(),
                multiaddr!(Ip4([0, 0, 0, 0]), Tcp(8000 + i as u16)),
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
            committee: Committee::new(pubks),
            keypairs: keyps,
        }
    }
}
