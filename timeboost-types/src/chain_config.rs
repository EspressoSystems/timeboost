use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    parent_chain_id: u64,
    parent_chain_rpc_url: String,
    parent_ibox_contr_addr: Address,
}

impl ChainConfig {
    pub fn new(chain_id: u64, rpc_url: Url, ibox_addr: Address) -> Self {
        Self {
            parent_chain_id: chain_id,
            parent_chain_rpc_url: rpc_url.to_string(),
            parent_ibox_contr_addr: ibox_addr,
        }
    }
    pub fn parent_chain_id(&self) -> u64 {
        self.parent_chain_id
    }

    pub fn parent_chain_rpc_url(&self) -> &String {
        &self.parent_chain_rpc_url
    }

    pub fn parent_ibox_contr_addr(&self) -> Address {
        self.parent_ibox_contr_addr
    }
}
