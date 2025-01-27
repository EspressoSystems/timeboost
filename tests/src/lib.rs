use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use multisig::{Committee, Keypair, PublicKey};
use timeboost_utils::unsafe_zero_keypair;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rbc;

pub struct Group {
    pub size: usize,
    pub peers: HashMap<PublicKey, SocketAddr>,
    pub committee: Committee,
    pub keypairs: Vec<Keypair>,
}

impl Group {
    pub fn new(size: usize) -> Self {
        let keypairs = (0..size as u64)
            .map(unsafe_zero_keypair)
            .collect::<Vec<_>>();
        let mut addrs = vec![];
        let mut pubks = vec![];

        for (i, kpr) in keypairs.iter().enumerate() {
            pubks.push((i as u8, kpr.public_key()));
            let port = portpicker::pick_unused_port().expect("could not find an open port");
            addrs.push(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }

        let peers: HashMap<PublicKey, SocketAddr> = pubks
            .iter()
            .zip(addrs.clone())
            .map(|(pk, addr)| (pk.1, addr))
            .collect();

        Self {
            size,
            peers,
            committee: Committee::new(pubks),
            keypairs,
        }
    }
}
