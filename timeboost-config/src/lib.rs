mod chain;
mod committee;
mod contract;
mod node;

use std::path::{Path, PathBuf};

pub use chain::{ChainConfig, ChainConfigBuilder};
pub use committee::{CommitteeConfig, CommitteeDefinition, CommitteeMember, MemberFile};
pub use contract::CommitteeContract;
pub use contract::fetch_current;
pub use node::{
    CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, GRPC_API_PORT_OFFSET, HTTP_API_PORT_OFFSET,
};
pub use node::{Espresso, Net, NodeConfig, NodeKeypair, NodeKeys};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Debug, thiserror::Error)]
#[error("config error {0}: {1}")]
pub struct ConfigError(PathBuf, #[source] Box<dyn std::error::Error + Send + Sync>);

pub(crate) async fn read_toml<T, P>(path: P) -> Result<T, ConfigError>
where
    T: DeserializeOwned,
    P: AsRef<Path>,
{
    let s = tokio::fs::read_to_string(path.as_ref())
        .await
        .map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))?;
    toml::from_str(&s).map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))
}

pub(crate) async fn write_toml<T, P>(val: &T, path: P) -> Result<(), ConfigError>
where
    T: Serialize,
    P: AsRef<Path>,
{
    let s =
        toml::to_string_pretty(val).map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))?;
    tokio::fs::write(path.as_ref(), s)
        .await
        .map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))
}
