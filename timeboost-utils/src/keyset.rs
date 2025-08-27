use std::{fmt, fs, path::Path, time::Duration};

use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_types::{ChainConfig, Timestamp};
use tokio::time::sleep;
use tracing::{error, info};

use crate::Blackbox;

/// Config for each node, containing private keys, public keys, chain_config, network addresses etc
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub net: NodeNetConfig,
    pub keys: NodeKeyConfig,
    pub chain_config: ChainConfig,
}

/// Network addresses in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNetConfig {
    pub sailfish: Address,
    pub internal: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<Address>,
}

impl NodeNetConfig {
    pub fn new(sailfish: Address, internal: Option<Address>, nitro: Option<Address>) -> Self {
        let internal = internal.unwrap_or(sailfish.clone().with_port(sailfish.port() + 3000));
        Self {
            sailfish,
            internal,
            nitro,
        }
    }

    pub fn decrypter(&self) -> Address {
        Self::decrypt_address_from(&self.sailfish)
    }

    pub fn decrypt_address_from(sailfish: &Address) -> Address {
        sailfish.clone().with_port(sailfish.port() + 1000)
    }

    pub fn certifier(&self) -> Address {
        Self::certifier_address_from(&self.sailfish)
    }

    pub fn certifier_address_from(sailfish: &Address) -> Address {
        sailfish.clone().with_port(sailfish.port() + 2000)
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
    pub secret: Blackbox,
    pub public: Blackbox,
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
    pub dkg_enc_key: Blackbox,
    pub sailfish_address: Address,
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
[net]
sailfish_address = '127.0.0.1:8000'
decrypt_address = '127.0.0.1:9000'
certifier_address = '127.0.0.1:10000'
internal_address = '127.0.0.1:11000'

[keys]
signing_key = 'eiwaGN1NNaQdbnR9FsjKzUeLghQZsTLPjiL4RcQgfLoX'
dh_key = 'AZrLbV37HAGhBWh49JHzup6Wfpu2AAGWGJJnxCDJibiY'
dkg_enc_key = '8t9PdQ61NwF9n7RU1du43C95ndSs6jn2EM7gRCfutVo2YXh6dyXAJiEWhpfYtPUv9gK'

[chain_config]
parent_chain_id = 31337
parent_chain_rpc_url = 'http://127.0.0.1:8545/'
parent_ibox_contr_addr = '0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f'
parent_block_tag = 'finalized'
key_manager_contr_addr = '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512'

[private]
signing_key = '3hzb3bRzn3dXSV1iEVE6mU4BF2aS725s8AboRxLwULPp'
dh_key = 'BB3zUfFQGfw3sL6bpp1JH1HozK6ehEDmRGoiCpQH62rZ'
dkg_dec_key = 'AgrGYiNQMqPpLgwPTuCV5aww6kpcoAQnf4xuFukTEtkL1'
    "#;

    use super::NodeConfig;

    #[test]
    fn serialisation_roundtrip() {
        let a = NodeConfig::read_string(CONFIG).unwrap();
        let b = NodeConfig::read_string(&a.to_string()).unwrap();
        assert_eq!(a, b);
    }
}
