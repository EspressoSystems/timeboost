use std::{fmt, fs, path::Path, time::Duration};

use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use timeboost_types::{ChainConfig, Timestamp};
use tokio::time::sleep;
use tracing::{error, info};

/// Config for each node, containing private keys, public keys, chain_config, network addresses etc
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub net: NodeNetConfig,
    pub keys: NodeKeyConfig,
    pub chain_config: ChainConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_addr: Option<Address>,
    #[serde(default)]
    pub private: Option<PrivateKeys>,
}

/// Network addresses in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNetConfig {
    pub sailfish_address: Address,
    pub decrypt_address: Address,
    pub certifier_address: Address,
    pub internal_address: Address,
}

/// Public key materials in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeyConfig {
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,
    /// public key for encryption/decryption used in DKG or key resharing for secure communication
    #[serde(with = "dkgenckey")]
    pub dkg_enc_key: DkgEncKey,
}

/// Private key materials in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeys {
    signing_key: multisig::SecretKey,
    dh_key: x25519::SecretKey,
    /// secret key for encryption/decryption used in DKG or key resharing for secure communication
    #[serde(with = "dkgdeckey")]
    dkg_dec_key: DkgDecKey,
}

impl PrivateKeys {
    pub fn new(
        signing_key: multisig::SecretKey,
        dh_key: x25519::SecretKey,
        dkg_dec_key: DkgDecKey,
    ) -> Self {
        Self {
            signing_key,
            dh_key,
            dkg_dec_key,
        }
    }

    pub fn signing_key(&self) -> &multisig::SecretKey {
        &self.signing_key
    }

    pub fn dh_key(&self) -> &x25519::SecretKey {
        &self.dh_key
    }

    pub fn dkg_dec_key(&self) -> &DkgDecKey {
        &self.dkg_dec_key
    }
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

macro_rules! mk_serde_mod {
    ($module:ident, $type:ident) => {
        mod $module {
            use super::$type;
            use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

            pub fn serialize<S>(x: &$type, s: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                bs58::encode(x.to_bytes()).into_string().serialize(s)
            }

            pub fn deserialize<'de, D>(d: D) -> Result<$type, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(d)?;
                let v = bs58::decode(&s).into_vec().map_err(de::Error::custom)?;
                let c = bincode::config::standard().with_limit::<8192>();
                let k = bincode::serde::decode_from_slice(&v, c).map_err(de::Error::custom)?;
                Ok(k.0)
            }
        }
    };
}

mk_serde_mod!(dkgenckey, DkgEncKey);
mk_serde_mod!(dkgdeckey, DkgDecKey);

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
    #[serde(with = "dkgenckey")]
    pub dkg_enc_key: DkgEncKey,
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
