use core::fmt;
use std::{path::Path, str::FromStr};

use crate::{ChainConfig, ConfigError};
use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};

pub const DECRYPTER_PORT_OFFSET: u16 = 100;
pub const CERTIFIER_PORT_OFFSET: u16 = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub net: NodeNet,
    pub keys: NodeKeys,
    pub chain: ChainConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNet {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeys {
    pub signing: NodeKeypair<multisig::SecretKey, multisig::PublicKey>,
    pub dh: NodeKeypair<x25519::SecretKey, x25519::PublicKey>,
    pub dkg: NodeKeypair<DkgDecKey, DkgEncKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeypair<SK, PK> {
    pub secret: SK,
    pub public: PK,
}

impl NodeConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        tokio::fs::read_to_string(path.as_ref())
            .await
            .map_err(|e| ConfigError(Box::new(e)))?
            .parse()
    }
}

impl FromStr for NodeConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| ConfigError(Box::new(e)))
    }
}

impl fmt::Display for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
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
