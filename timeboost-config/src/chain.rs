use std::path::Path;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use bon::Builder;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{ConfigError, read_toml};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
#[serde(rename_all = "kebab-case")]
pub struct ChainConfig {
    pub id: u64,
    pub rpc_url: Url,
    pub websocket_url: Url,
    pub key_management_contract: Address,
    pub inbox_contract: Address,
    pub inbox_block_tag: BlockNumberOrTag,
}

impl ChainConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        read_toml(path).await
    }
}
