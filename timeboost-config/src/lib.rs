use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use tracing::error;

mod chain;

pub use chain::{ChainConfig, ChainConfigBuilder, ParentChain, ParentChainBuilder};

pub const DECRYPTER_PORT_OFFSET: u16 = 1;
pub const CERTIFIER_PORT_OFFSET: u16 = 2;

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

/// Key materials in [`NodeConfig`]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeyConfig {
    pub signing: NodeKeypairConfig<multisig::SecretKey, multisig::PublicKey>,
    pub dh: NodeKeypairConfig<x25519::SecretKey, x25519::PublicKey>,
    pub dkg: NodeKeypairConfig<DkgDecKey, DkgEncKey>,
}

/// A keypair
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeypairConfig<SK, PK> {
    pub secret: SK,
    pub public: PK,
}

/// Config for the new committee info to be updated to the KeyManager contract.
/// This file is written during per-node run of `mkconfig`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub effective_timestamp: jiff::Timestamp,
    #[serde(default)]
    pub members: Vec<CommitteeMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,
    pub dkg_enc_key: DkgEncKey,
    pub public_address: Address,
}

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct ConfigError(#[source] Box<dyn std::error::Error + Send + Sync>);

macro_rules! ConfigImpls {
    ($t:ty) => {
        impl core::str::FromStr for $t {
            type Err = ConfigError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                toml::from_str(s).map_err(|e| ConfigError(Box::new(e)))
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let s = toml::to_string_pretty(self).map_err(|_| core::fmt::Error)?;
                f.write_str(&s)
            }
        }

        impl $t {
            pub async fn read<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
                tokio::fs::read_to_string(path.as_ref())
                    .await
                    .map_err(|e| ConfigError(Box::new(e)))?
                    .parse()
            }
        }
    };
}

ConfigImpls!(NodeConfig);
ConfigImpls!(CommitteeConfig);

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
secret = "Cab231aFJTQYmZV7Qw4qa2x49K58fbyTEsM4Tz2CKi1"
public = "7jdMG9MUWoN4avAc3mbf2tTTGdKSmmGZWTgR3NJ9hJPn6dHj9Vdqspcs3j6zTThfjC"

[chain]
namespace = 10101

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
        let a: NodeConfig = CONFIG.parse().unwrap();
        let b: NodeConfig = a.to_string().parse().unwrap();
        assert_eq!(a, b);
    }
}
