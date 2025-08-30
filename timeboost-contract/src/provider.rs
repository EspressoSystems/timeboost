//! Helper functions to build Ethereum [providers](https://docs.rs/alloy/latest/alloy/providers/trait.Provider.html)
//! Partial Credit: <https://github.com/EspressoSystems/espresso-network/tree/main/contracts/rust/deployer>

use alloy::{
    network::EthereumWallet,
    providers::ProviderBuilder,
    signers::local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
    transports::http::reqwest::Url,
};
use timeboost_types::HttpProviderWithWallet;

/// Build a local signer from wallet mnemonic and account index
pub fn build_signer(
    mnemonic: String,
    account_index: u32,
) -> Result<PrivateKeySigner, LocalSignerError> {
    MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .index(account_index)?
        .build()
}

/// a handy thin wrapper around wallet builder and provider builder that directly
/// returns an instantiated `Provider` with default fillers with wallet, ready to send tx
pub fn build_provider(
    mnemonic: String,
    account_index: u32,
    url: Url,
) -> Result<HttpProviderWithWallet, LocalSignerError> {
    let signer = build_signer(mnemonic, account_index)?;
    let wallet = EthereumWallet::from(signer);
    Ok(ProviderBuilder::new().wallet(wallet).connect_http(url))
}
