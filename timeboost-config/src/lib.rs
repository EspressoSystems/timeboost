mod chain;
mod committee;
mod node;

use std::path::PathBuf;

pub use chain::{ChainConfig, ChainConfigBuilder, ParentChain, ParentChainBuilder};
pub use committee::{CommitteeConfig, CommitteeMember};
pub use node::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET};
pub use node::{Espresso, InternalNet, NodeConfig, NodeKeypair, NodeKeys, NodeNet, PublicNet};

#[derive(Debug, thiserror::Error)]
#[error("config error {0}: {1}")]
pub struct ConfigError(PathBuf, #[source] Box<dyn std::error::Error + Send + Sync>);
