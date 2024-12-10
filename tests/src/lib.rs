use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::{Keypair, PublicKey};
use timeboost_networking::network::client::{derive_libp2p_multiaddr, derive_libp2p_peer_id};
use timeboost_utils::{PeerConfig, ValidatorConfig};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;

#[cfg(test)]
mod rbc;

pub struct Group {
    pub size: usize,
    pub addrs: Vec<Multiaddr>,
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    pub staked_nodes: Vec<PeerConfig<PublicKey>>,
    pub committee: StaticCommittee,
    pub peer_ids: Vec<PeerId>,
    pub keypairs: Vec<Keypair>,
}

impl Group {
    pub fn new(size: usize) -> Self {
        let keypairs = (0..size as u64).map(Keypair::zero).collect::<Vec<_>>();
        let mut addrs = vec![];
        let mut peer_ids = vec![];
        let mut vcgfs = vec![];

        for (i, kpr) in keypairs.iter().enumerate() {
            let cfg = ValidatorConfig::generated_from_seed_indexed(
                Keypair::ZERO_SEED,
                i as u64,
                1,
                false,
            );
            addrs.push(derive_libp2p_multiaddr(&format!("127.0.0.1:{}", 8000 + i as u16)).unwrap());
            vcgfs.push(cfg);
            peer_ids.push(derive_libp2p_peer_id::<PublicKey>(kpr.private_key()).unwrap());
        }

        let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = peer_ids
            .iter()
            .zip(addrs.iter())
            .map(|(peer_id, addr)| (*peer_id, addr.clone()))
            .collect();

        let staked_nodes: Vec<PeerConfig<PublicKey>> =
            vcgfs.iter().map(|c| c.public_config()).collect();

        Self {
            size,
            peer_ids,
            bootstrap_nodes,
            staked_nodes,
            committee: StaticCommittee::new(keypairs.iter().map(|k| *k.public_key()).collect()),
            keypairs,
            addrs,
        }
    }
}
