use std::collections::HashMap;

use libp2p_identity::PeerId;
use multisig::PublicKey;
use serde::{Deserialize, Serialize};
use timeboost_core::types::NodeId;
use timeboost_networking::derive_peer_id;
use timeboost_utils::{unsafe_zero_keypair, PeerConfig, ValidatorConfig};
use tracing::error;

/// The `CommitteeBase` defines which underlying commitee basis is used when
/// calculating (or polling for) public keys of the other nodes in the network.
#[derive(Debug, Clone, Copy, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitteeBase {
    Docker,
    Local,
    /// The Network configuration allows for us to use the fake-contract server
    /// for registering instances. This is a trusted-environment-only method as
    /// it is a generally insecure method, and not suitable for production.
    Network,
}

/// The response payload for the registrant.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReadyResponse {
    node_id: u64,
    ip_addr: String,
    public_key: Vec<u8>,
}

/// The response payload for the network startup.
#[derive(Debug, Deserialize, Serialize)]
pub struct StartResponse {
    started: bool,
    committee: Vec<ReadyResponse>,
}

/// A contract for managing the committee of nodes, this is a placeholder for now.
pub struct CommitteeContract {
    /// A bootstrap node is a map from its public key to its peer-id/bind address combo.
    bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
}

impl Default for CommitteeContract {
    /// Default to using the docker config.
    fn default() -> Self {
        Self::new(CommitteeBase::Docker, 5, None)
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
                // Docker uses the docker network IP address for config, but we bind according to
                // the usual semantics of 127.* or 0.* for localhost.
                // Here, incrementing the port is not explicitly necessary, but since docker-compose
                // runs locally, we do it to be consistent. Note that this IP needs to match
                // whatever the network configuration in the `docker-compose.yml` file is. If that
                // changes, then this will break.
                CommitteeBase::Docker => format!("172.20.0.{}:{}", 2 + i, 8000 + i),
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

    pub async fn new_from_network(id: NodeId, url: reqwest::Url) -> Self {
        // First, submit our public key (generated deterministically).
        let client = reqwest::Client::new();
        let timeout_duration = std::time::Duration::from_secs(60);

        let kpr = unsafe_zero_keypair(u64::from(id));
        let peer_id = derive_peer_id::<PublicKey>(&kpr.secret_key()).unwrap();

        tokio::time::timeout(timeout_duration, async {
            loop {
                match client
                    .post(url.clone().join("ready/").expect("valid url"))
                    .body(
                        serde_json::to_string(
                            &serde_json::json!({ "node_id": u64::from(id), "public_key": kpr.public_key().as_bytes() }),
                        )
                        .unwrap(),
                    )
                    .send()
                    .await
                {
                    Ok(response) => match response.json::<ReadyResponse>().await {
                        Ok(payload) => break payload,
                        Err(e) => {
                            error!(%e, "failed to parse response payload");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    },
                    Err(e) => {
                        error!(%e, "http request failed");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        })
        .await.expect("response before timeout");

        // Run the timeout again, except waiting for the full system startup
        let committee_data = tokio::time::timeout(timeout_duration, async {
            loop {
                match client
                    .get(url.clone().join("start/").expect("valid url"))
                    .send()
                    .await
                {
                    Ok(response) => match response.json::<StartResponse>().await {
                        Ok(payload) => {
                            if payload.started {
                                break payload;
                            }

                            // Otherwise, wait a sec before checking again
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        Err(e) => {
                            error!(%e, "failed to parse response payload");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    },
                    Err(e) => {
                        error!(%e, "http request failed");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        })
        .await
        .expect("commitee to be created before timeout");

        let mut bootstrap_nodes = HashMap::new();
        let mut staked_nodes = vec![];
        for c in committee_data.committee.into_iter() {
            let cfg = ValidatorConfig::<PublicKey>::generated_from_seed_indexed(
                [0; 32], c.node_id, 1, false,
            );
            bootstrap_nodes.insert(kpr.public_key(), (peer_id, c.ip_addr));
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
    pub fn bootstrap_nodes(&self) -> HashMap<PublicKey, (PeerId, String)> {
        self.bootstrap_nodes.clone()
    }
}
