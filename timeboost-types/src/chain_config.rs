use alloy::eips::BlockNumberOrTag;
use alloy::network::EthereumWallet;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{HttpProvider, HttpProviderWithWallet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    parent_chain_id: u64,
    parent_chain_rpc_url: Url,
    parent_ibox_contr_addr: Address,
    parent_block_tag: BlockNumberOrTag,
    key_manager_contr_addr: Address,
}

impl ChainConfig {
    pub fn new(
        chain_id: u64,
        rpc_url: Url,
        ibox_addr: Address,
        parent_block_tag: BlockNumberOrTag,
        key_manager_contr_addr: Address,
    ) -> Self {
        Self {
            parent_chain_id: chain_id,
            parent_chain_rpc_url: rpc_url,
            parent_ibox_contr_addr: ibox_addr,
            parent_block_tag,
            key_manager_contr_addr,
        }
    }
    pub fn parent_chain_id(&self) -> u64 {
        self.parent_chain_id
    }

    pub fn parent_chain_rpc_url(&self) -> &Url {
        &self.parent_chain_rpc_url
    }

    pub fn parent_ibox_contr_addr(&self) -> Address {
        self.parent_ibox_contr_addr
    }

    pub fn parent_block_tag(&self) -> BlockNumberOrTag {
        self.parent_block_tag
    }

    pub fn key_manager_contr_addr(&self) -> Address {
        self.key_manager_contr_addr
    }

    /// Returns a provider to the parent chain,
    /// If wallet is provided, the returned provider can directly write to blockchain (i.e. send tx)
    /// else, the returned provider can only read from blockchain (i.e. call and read states)
    pub fn provider(&self) -> HttpProvider {
        ProviderBuilder::new().connect_http(self.parent_chain_rpc_url.clone())
    }

    pub fn provider_with_wallet(&self, wallet: EthereumWallet) -> HttpProviderWithWallet {
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.parent_chain_rpc_url.clone())
    }
}
