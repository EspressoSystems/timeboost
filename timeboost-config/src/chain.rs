use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use bon::Builder;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
#[serde(rename_all = "kebab-case")]
pub struct ChainConfig {
    pub id: u64,
    pub rpc_url: Url,
    pub inbox_contract: Address,
    pub inbox_block_tag: BlockNumberOrTag,
}
