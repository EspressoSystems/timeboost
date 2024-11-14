use std::path::Path;

use hotshot_types::PeerConfig;
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use timeboost_core::types::PublicKey;

use crate::config::Config;

/// A contract for managing the committee of nodes, this is a placeholder for now.
pub struct CommitteeContract {
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
}

impl Default for CommitteeContract {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitteeContract {
    /// This will change, right now we pre-seed the contract with a fixed number of nodes
    /// in the fake committee. Each node's ID will be known ahead of time.
    pub fn new() -> Self {
        // Read from the config file 'example_config.toml' and get the setup from there.
        let config = toml::from_str::<Config>(include_str!("../../../docker_config.toml")).unwrap();

        // Make a new committee contract with the given setup.
        Self {
            bootstrap_nodes: config.bootstrap_nodes,
            staked_nodes: config.staked_nodes,
        }
    }

    /// Fetch the current committee of nodes from the contract, placeholder for now.
    pub fn staked_nodes(&self) -> Vec<PeerConfig<PublicKey>> {
        self.staked_nodes.to_vec()
    }

    /// Fetch the current bootstrap nodes from the contract, also a placeholder for now.
    pub fn bootstrap_nodes(&self) -> Vec<(PeerId, Multiaddr)> {
        self.bootstrap_nodes.to_vec()
    }
}
