use std::collections::HashMap;

use libp2p_identity::PeerId;
use multisig::PublicKey;
use timeboost_core::types::NodeId;
use timeboost_networking::derive_peer_id;
use timeboost_utils::{unsafe_zero_keypair, PeerConfig, ValidatorConfig};

/// The `CommitteeBase` defines which underlying commitee basis is used when
/// calculating (or polling for) public keys of the other nodes in the network.
#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitteeBase {
    Local,
    /// The Network configuration allows for us to use the fake-contract server
    /// for registering instances. This is a trusted-environment-only method as
    /// it is a generally insecure method, and not suitable for production.
    Network,
}

/// A contract for managing the committee of nodes, this is a placeholder for now.
#[derive(Debug, Clone)]
pub struct CommitteeContract {
    /// A bootstrap node is a map from its public key to its peer-id/bind address combo.
    bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
}

impl Default for CommitteeContract {
    /// Default to using the docker config.
    fn default() -> Self {
        Self::new(CommitteeBase::Local, 5, None)
    }
}

impl CommitteeContract {
    /// Create a new committee contract with 5 nodes. This is a placeholder method for what will
    /// eventually be read from an actual smart contract.
    pub fn new(base: CommitteeBase, size: u16, skip_bootstrap_id: Option<u16>) -> Self {
        Self::new_n(base, size, skip_bootstrap_id)
    }

    /// Create a new committee contract with `n` nodes. This is a placeholder method for what will
    /// eventually be read from an actual smart contract.
    pub fn new_n(base: CommitteeBase, n: u16, skip_bootstrap_id: Option<u16>) -> Self {
        let mut bootstrap_nodes = HashMap::new();
        let mut staked_nodes = vec![];

        for i in 0..n {
            let cfg = ValidatorConfig::<PublicKey>::generated_from_seed_indexed(
                [0; 32], i as u64, 1, false,
            );
            let kpr = unsafe_zero_keypair(i as u64);
            let peer_id = derive_peer_id::<PublicKey>(&kpr.secret_key()).unwrap();
            let bind_addr = match base {
                CommitteeBase::Local => format!("127.0.0.1:{}", 8000 + i),
                _ => {
                    // If we get here that's a mistake
                    unreachable!();
                }
            };
            staked_nodes.push(cfg.public_config());

            // Dont add a late start node to bootstrap so the network can start without it
            if let Some(skip_id) = skip_bootstrap_id {
                if skip_id == i {
                    continue;
                }
            }
            bootstrap_nodes.insert(kpr.public_key(), (peer_id, bind_addr));
        }

        Self {
            bootstrap_nodes,
            staked_nodes,
        }
    }

    pub async fn new_from_network(node_id: NodeId, node_port: u16, url: reqwest::Url) -> Self {
        let kpr = unsafe_zero_keypair(u64::from(node_id));

        // First, submit that we're ready
        crate::contracts::initializer::submit_ready(
            u64::from(node_id),
            node_port,
            kpr,
            url.clone(),
        )
        .await
        .expect("ready submission to succeed");

        // Then, wait for the rest of the committee to be ready.
        let (bootstrap_nodes, staked_nodes) =
            crate::contracts::initializer::wait_for_committee(url)
                .await
                .expect("committee to be ready");
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
    pub fn bootstrap_nodes(&self) -> HashMap<PublicKey, (PeerId, String)> {
        self.bootstrap_nodes.clone()
    }
}
