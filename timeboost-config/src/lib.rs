mod chain;
mod committee;
mod node;
mod service;

use std::path::{Path, PathBuf};

pub use chain::{ChainConfig, ChainConfigBuilder};
pub use committee::{CommitteeConfig, CommitteeMember};
pub use node::{
    CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, GRPC_API_PORT_OFFSET, HTTP_API_PORT_OFFSET,
};
pub use node::{Espresso, Net, NodeConfig, NodeKeypair, NodeKeys};
use serde::de::DeserializeOwned;
pub use service::{ConfigService, ServiceConfig, config_service};

#[derive(Debug, thiserror::Error)]
#[error("config error {0}: {1}")]
pub struct ConfigError(PathBuf, #[source] Box<dyn std::error::Error + Send + Sync>);

pub(crate) async fn read_toml<T, P>(path: P) -> Result<T, ConfigError>
where
    T: DeserializeOwned,
    P: AsRef<Path>
{
    let s = tokio::fs::read_to_string(path.as_ref())
        .await
        .map_err(|e| ConfigError(path.as_ref().into(), Box::new(e)))?;
    toml::from_str(&s).map_err(|e| ConfigError(PathBuf::new(), Box::new(e)))
}
