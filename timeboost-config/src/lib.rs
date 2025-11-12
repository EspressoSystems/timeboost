mod chain;
mod committee;
mod node;
mod service;

use std::path::PathBuf;

pub use chain::{ChainConfig, ChainConfigBuilder};
pub use committee::{CommitteeConfig, CommitteeMember};
pub use node::{
    CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, GRPC_API_PORT_OFFSET, HTTP_API_PORT_OFFSET,
};
pub use node::{Espresso, Net, NodeConfig, NodeKeypair, NodeKeys};
pub use service::{ConfigService, FileConfigService, config_service};

#[derive(Debug, thiserror::Error)]
#[error("config error {0}: {1}")]
pub struct ConfigError(PathBuf, #[source] Box<dyn std::error::Error + Send + Sync>);
