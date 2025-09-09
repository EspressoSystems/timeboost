use core::fmt;
use std::{path::Path, str::FromStr};

use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::DkgEncKey;

use crate::ConfigError;

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

impl CommitteeConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        tokio::fs::read_to_string(path.as_ref())
            .await
            .map_err(|e| ConfigError(Box::new(e)))?
            .parse()
    }
}

impl FromStr for CommitteeConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| ConfigError(Box::new(e)))
    }
}

impl fmt::Display for CommitteeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}
