use alloy::{
    network::{Ethereum, EthereumWallet},
    providers::{
        ProviderBuilder, RootProvider,
        fillers::{FillProvider, JoinFill, WalletFiller},
        layers::AnvilProvider,
        utils::JoinedRecommendedFillers,
    },
};
use url::Url;

/// Type alias that connects to providers with recommended fillers and wallet
/// use `<HttpProviderWithWallet as WalletProvider>::wallet()` to access internal wallet
/// use `<HttpProviderWithWallet as WalletProvider>::default_signer_address(&provider)` to get
/// wallet address
pub type HttpProviderWithWallet = FillProvider<
    JoinFill<JoinedRecommendedFillers, WalletFiller<EthereumWallet>>,
    RootProvider,
    Ethereum,
>;

/// Provider connected to blockchain URL with read only access
pub type HttpProvider = FillProvider<JoinedRecommendedFillers, RootProvider, Ethereum>;

/// Similar to `HttpProviderWithWallet` except the network being the Anvil test blockchain
pub type TestProviderWithWallet = FillProvider<
    JoinFill<JoinedRecommendedFillers, WalletFiller<EthereumWallet>>,
    AnvilProvider<RootProvider>,
    Ethereum,
>;

pub fn provider(rpc: &Url) -> HttpProvider {
    ProviderBuilder::new().connect_http(rpc.clone())
}

pub fn provider_with_wallet(rpc: &Url, wallet: EthereumWallet) -> HttpProviderWithWallet {
    ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc.clone())
}
