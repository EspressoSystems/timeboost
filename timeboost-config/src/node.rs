use core::fmt;
use std::path::{Path, PathBuf};

use crate::{ChainConfig, ConfigError};
use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use url::Url;

pub const DECRYPTER_PORT_OFFSET: u16 = 1;
pub const CERTIFIER_PORT_OFFSET: u16 = 2;
pub const HTTP_API_PORT_OFFSET: u16 = 3;
pub const GRPC_API_PORT_OFFSET: u16 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub stamp: PathBuf,
    pub net: Net,
    pub keys: NodeKeys,
    pub chain: ChainConfig,
    pub espresso: Espresso,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Net {
    pub bind: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<Address>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeys {
    pub signing: NodeKeypair<multisig::SecretKey, multisig::PublicKey>,
    pub dh: NodeKeypair<x25519::SecretKey, x25519::PublicKey>,
    pub dkg: NodeKeypair<DkgDecKey, DkgEncKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKeypair<SK, PK> {
    pub secret: SK,
    pub public: PK,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Espresso {
    pub namespace: u64,
    pub base_url: Url,
    pub builder_base_url: Option<Url>,
    pub websockets_base_url: Url,
    pub max_transaction_size: usize,
}

impl NodeConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let s = tokio::fs::read_to_string(path.as_ref())
            .await
            .map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))?;

        toml::from_str(&s).map_err(|e| ConfigError(PathBuf::new(), Box::new(e)))
    }
}

impl fmt::Display for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}
