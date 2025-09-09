use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use bon::Builder;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ChainConfig {
    pub namespace: u64,
    pub parent: ParentChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ParentChain {
    pub id: u64,
    pub rpc_url: Url,
    pub ibox_contract: Address,
    pub block_tag: BlockNumberOrTag,
    pub key_manager_contract: Address,
}
