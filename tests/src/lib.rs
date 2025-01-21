use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use multisig::{Committee, Keypair, PublicKey};
use timeboost_utils::{unsafe_zero_keypair, PeerConfig, ValidatorConfig};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rbc;

pub struct Group {
    pub size: usize,
    pub addrs: Vec<SocketAddr>,
    pub bootstrap_nodes: HashMap<PublicKey, SocketAddr>,
    pub staked_nodes: Vec<PeerConfig<PublicKey>>,
    pub committee: Committee,
    pub keypairs: Vec<Keypair>,
}

impl Group {
    pub fn new(size: usize) -> Self {
        let keypairs = (0..size as u64)
            .map(unsafe_zero_keypair)
            .collect::<Vec<_>>();
        let mut addrs = vec![];
        let mut vcgfs = vec![];
        let mut pubks = vec![];

        for (i, kpr) in keypairs.iter().enumerate() {
            let cfg = ValidatorConfig::generated_from_seed_indexed([0; 32], i as u64, 1, false);
            pubks.push((i as u8, kpr.public_key()));
            let port = portpicker::pick_unused_port().expect("Could not find an open port");
            addrs.push(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
            vcgfs.push(cfg);
        }

        let bootstrap_nodes: HashMap<PublicKey, SocketAddr> = pubks
            .iter()
            .zip(addrs.clone())
            .map(|(pk, addr)| (pk.1, addr))
            .collect();

        let staked_nodes: Vec<PeerConfig<PublicKey>> =
            vcgfs.iter().map(|c| c.public_config()).collect();

        Self {
            size,
            bootstrap_nodes,
            staked_nodes,
            committee: Committee::new(pubks),
            keypairs,
            addrs,
        }
    }
}
