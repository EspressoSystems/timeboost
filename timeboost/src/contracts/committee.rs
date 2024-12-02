use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use timeboost_core::types::{Keypair, PublicKey};
use timeboost_networking::network::client::{derive_libp2p_multiaddr, derive_libp2p_peer_id};
use timeboost_utils::{PeerConfig, ValidatorConfig};

#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitteeBase {
    Docker,
    Local,
}

/// A contract for managing the committee of nodes, this is a placeholder for now.
pub struct CommitteeContract {
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
}

impl Default for CommitteeContract {
    /// Default to using the docker config.
    fn default() -> Self {
        Self::new(CommitteeBase::Docker)
    }
}

impl CommitteeContract {
    /// Create a new committee contract with 5 nodes. This is a placeholder method for what will
    /// eventually be read from an actual smart contract.
    pub fn new(base: CommitteeBase) -> Self {
        Self::new_n(base, 5)
    }

    /// Create a new committee contract with `n` nodes. This is a placeholder method for what will
    /// eventually be read from an actual smart contract.
    pub fn new_n(base: CommitteeBase, n: u16) -> Self {
        let mut bootstrap_nodes = vec![];
        let mut staked_nodes = vec![];

        for i in 0..n {
            let cfg = ValidatorConfig::<PublicKey>::generated_from_seed_indexed(
                Keypair::ZERO_SEED,
                i as u64,
                1,
                false,
            );
            let kpr = Keypair::zero(i as u64);
            let peer_id = derive_libp2p_peer_id::<PublicKey>(kpr.private_key()).unwrap();
            let bind_addr = match base {
                CommitteeBase::Local => {
                    derive_libp2p_multiaddr(&format!("127.0.0.1:{}", 8000 + i)).unwrap()
                }
                // Docker uses the docker network IP address for config, but we bind according to
                // the usual semantics of 127.* or 0.* for localhost.
                // Here, incrementing the port is not explicitly necessary, but since docker-compose
                // runs locally, we do it to be consistent.
                CommitteeBase::Docker => {
                    derive_libp2p_multiaddr(&format!("172.20.0.{}:{}", 2 + i, 8000 + i)).unwrap()
                }
            };

            bootstrap_nodes.push((peer_id, bind_addr));
            staked_nodes.push(cfg.public_config());
        }

        Self {
            bootstrap_nodes,
            staked_nodes,
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
