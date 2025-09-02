use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use bon::Builder;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ChainConfig {
    namespace: u64,
    parent: ParentChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Builder)]
pub struct ParentChain {
    id: u64,
    rpc_url: Url,
    ibox_contract: Address,
    block_tag: BlockNumberOrTag,
    key_manager_contract: Address,
}

impl ChainConfig {
    pub fn namespace(&self) -> u64 {
        self.namespace
    }

    pub fn parent(&self) -> &ParentChain {
        &self.parent
    }
}

impl ParentChain {
    pub fn chain_id(&self) -> u64 {
        self.id
    }

    pub fn rpc_url(&self) -> &Url {
        &self.rpc_url
    }

    pub fn ibox_contract(&self) -> &Address {
        &self.ibox_contract
    }

    pub fn block_tag(&self) -> BlockNumberOrTag {
        self.block_tag
    }

    pub fn key_manager_contract(&self) -> &Address {
        &self.key_manager_contract
    }
}
