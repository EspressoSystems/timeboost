use anyhow::Result;
use std::{fs, path::Path};
use timeboost_util::types::PeerConfig;

use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use serde::{Deserialize, Serialize};
use timeboost_core::types::PublicKey;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    pub staked_nodes: Vec<PeerConfig<PublicKey>>,
}

impl Config {
    pub fn new(path: &Path) -> Result<Self> {
        let config_str = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&config_str)?;
        Ok(config)
    }
}
