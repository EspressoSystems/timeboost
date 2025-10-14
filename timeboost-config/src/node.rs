use core::fmt;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{ChainConfig, ConfigError};
use anyhow::Result;
use cliquenet::Address;
use multisig::{CommitteeId, x25519};
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use url::Url;

pub const DECRYPTER_PORT_OFFSET: u16 = 100;
pub const CERTIFIER_PORT_OFFSET: u16 = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub committee: CommitteeId,
    pub stamp: PathBuf,
    pub net: NodeNet,
    pub keys: NodeKeys,
    pub chain: ChainConfig,
    pub espresso: Espresso,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeNet {
    pub public: PublicNet,
    pub internal: InternalNet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PublicNet {
    pub address: Address,
    pub http_api: Address,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Espresso {
    pub base_url: Url,
    pub builder_base_url: Url,
    pub websockets_base_url: Url,
    pub max_transaction_size: usize,
}

impl NodeConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        tokio::fs::read_to_string(path.as_ref())
            .await
            .map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))?
            .parse()
    }
}

impl FromStr for NodeConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| ConfigError(Path::new("").into(), Box::new(e)))
    }
}

impl fmt::Display for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}
