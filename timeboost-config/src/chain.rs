use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::{eips::BlockNumberOrTag, network::EthereumWallet};
use bon::Builder;
use serde::{Deserialize, Serialize};
use timeboost_types::{HttpProvider, HttpProviderWithWallet};
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

impl ParentChain {
    pub fn provider(&self) -> HttpProvider {
        ProviderBuilder::new().connect_http(self.rpc_url.clone())
    }

    pub fn provider_with_wallet(&self, wallet: EthereumWallet) -> HttpProviderWithWallet {
        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.rpc_url.clone())
    }
}
