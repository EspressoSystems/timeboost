use std::{fmt, fs, path::Path, time::Duration};

use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use timeboost_types::{ChainConfig, Timestamp};
use tokio::time::sleep;
use tracing::{error, info};

use crate::Bs58Bincode;

pub const DECRYPTER_PORT_OFFSET: u16 = 1000;
pub const CERTIFIER_PORT_OFFSET: u16 = 2000;

/// Config for each node, containing private keys, public keys, chain_config, network addresses etc
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub net: NodeNetConfig,
    pub keys: NodeKeyConfig,
    pub chain: ChainConfig,
}

/// Network addresses in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNetConfig {
    pub public: PublicNet,
    pub internal: InternalNet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicNet {
    pub address: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalNet {
    pub address: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<Address>,
}

impl NodeNetConfig {
    pub fn new(public: Address, internal: Address, nitro: Option<Address>) -> Self {
        Self {
            public: PublicNet { address: public },
            internal: InternalNet {
                address: internal,
                nitro,
            },
        }
    }
}

/// Key materials in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeyConfig {
    pub signing: NodeKeypairConfig<multisig::SecretKey, multisig::PublicKey>,
    pub dh: NodeKeypairConfig<x25519::SecretKey, x25519::PublicKey>,
    pub dkg: NodeEncodedKeypairConfig,
}

/// A keypair
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeypairConfig<SK, PK> {
    pub secret: SK,
    pub public: PK,
}

/// An encoded keypair
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEncodedKeypairConfig {
    pub secret: Bs58Bincode<DkgDecKey>,
    pub public: Bs58Bincode<DkgEncKey>,
}

impl NodeConfig {
    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read_to_string(path)?;
        Self::read_string(&data)
    }

    pub fn read_string(s: &str) -> Result<Self> {
        let config = toml::from_str(s)?;
        Ok(config)
    }
}

impl fmt::Display for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

/// Config for the new committee info to be updated to the KeyManager contract.
/// This file is written during per-node run of `mkconfig`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub effective_timestamp: Timestamp,
    #[serde(default)]
    pub members: Vec<CommitteeMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,
    pub dkg_enc_key: Bs58Bincode<DkgEncKey>,
    pub public_address: Address,
}

impl CommitteeConfig {
    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read_to_string(path)?;
        Self::read_string(&data)
    }

    pub fn read_string(s: &str) -> Result<Self> {
        let config = toml::from_str(s)?;
        Ok(config)
    }
}

impl fmt::Display for CommitteeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

/// NON PRODUCTION
/// This function takes the provided host and hits the health endpoint. This to ensure that when
/// initiating the network TCP stream that we do not try to hit a dead host, causing issues with
/// network startup.
pub async fn wait_for_live_peer(host: &Address) -> Result<()> {
    if host.is_ip() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    let url = format!("http://{host}/i/health");

    loop {
        info!(%host, %url, "establishing connection to load balancer");
        match client.get(&url).send().await {
            Ok(resp) => {
                info!(response = ?resp, "got response");
                if resp.status() == 200 {
                    return Ok(());
                }
            }
            Err(err) => {
                error!(%err, "failed to send request")
            }
        }
        sleep(Duration::from_secs(3)).await;
    }
}

#[cfg(test)]
mod tests {
    // generated via `just mkconfig 1`
    const CONFIG: &str = r#"
[net.public]
address = "127.0.0.1:8001"

[net.internal]
address = "127.0.0.1:11001"

[keys.signing]
secret = "AS9HxHVwMNyAYsdGntcD56iBbobBn7RPBi32qEBGDSSb"
public = "23as9Uo6W2AeGronB6nMpcbs8Nxo6CoJ769uePw9sf6Ud"

[keys.dh]
secret = "HeTQaTvq1337kSEd5jt4cdF35Touns1WB7xfs24sKxqM"
public = "3V1LzAgCwubtAb1MT1YgTH2scXg6d2bQEhhsAMeyNo6X"

[keys.dkg]
secret = "AmgWFmLHk3m1C5mfZnhToYDj2azuyh8d7GiEB3w3s8EBP"
public = "8rokdkmSKkupd7C9oPd3MBPuBANq6ZaQ7hA1uvoFeLmXanMK7ndXwVCy5vUTPkULA7G"

[chain.parent]
id = 31337
rpc_url = "http://127.0.0.1:8545/"
ibox_contract = "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f"
block_tag = "finalized"
key_manager_contract = "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35"
    "#;

    use super::NodeConfig;

    #[test]
    fn serialisation_roundtrip() {
        let a = NodeConfig::read_string(CONFIG).unwrap();
        let b = NodeConfig::read_string(&a.to_string()).unwrap();
        assert_eq!(a, b);
    }
}
