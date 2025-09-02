mod chain;
mod committee;
mod node;

pub use chain::{ChainConfig, ChainConfigBuilder, ParentChain, ParentChainBuilder};
pub use committee::{CommitteeConfig, CommitteeMember};
pub use node::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET};
pub use node::{InternalNet, NodeConfig, NodeKeypair, NodeKeys, NodeNet, PublicNet};

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct ConfigError(#[source] Box<dyn std::error::Error + Send + Sync>);
