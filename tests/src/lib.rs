use std::collections::HashMap;

use libp2p_identity::PeerId;
use multisig::{Committee, Keypair, PublicKey};
use timeboost_networking::p2p::client::derive_libp2p_peer_id;
use timeboost_utils::{unsafe_zero_keypair, PeerConfig, ValidatorConfig};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rbc;

pub struct Group {
    pub size: usize,
    pub addrs: Vec<String>,
    pub bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,
    pub staked_nodes: Vec<PeerConfig<PublicKey>>,
    pub committee: Committee,
    pub peer_ids: Vec<PeerId>,
    pub keypairs: Vec<Keypair>,
}

impl Group {
    pub fn new(size: usize) -> Self {
        let keypairs = (0..size as u64)
            .map(unsafe_zero_keypair)
            .collect::<Vec<_>>();
        let mut addrs = vec![];
        let mut peer_ids = vec![];
        let mut vcgfs = vec![];
        let mut pubks = vec![];

        for (i, kpr) in keypairs.iter().enumerate() {
            let cfg = ValidatorConfig::generated_from_seed_indexed([0; 32], i as u64, 1, false);
            pubks.push((i as u8, kpr.public_key()));
            addrs.push(format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().expect("Could not find an open port")
            ));
            vcgfs.push(cfg);
            peer_ids.push(derive_libp2p_peer_id::<PublicKey>(&kpr.secret_key()).unwrap());
        }

        let bootstrap_nodes: HashMap<PublicKey, (PeerId, String)> = pubks
            .iter()
            .zip(peer_ids.clone())
            .zip(addrs.clone())
            .map(|((pk, pid), addr)| (pk.1, (pid, addr)))
            .collect();

        let staked_nodes: Vec<PeerConfig<PublicKey>> =
            vcgfs.iter().map(|c| c.public_config()).collect();

        Self {
            size,
            peer_ids,
            bootstrap_nodes,
            staked_nodes,
            committee: Committee::new(pubks),
            keypairs,
            addrs,
        }
    }
}
