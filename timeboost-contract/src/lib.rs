//! Timeboost Contract Bindings, Deployer and API bridges.
//!
//! This crate provides Rust bindings and API to interact with smart contracts,

use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, WalletProvider},
    transports::http::reqwest::Url,
};
use anyhow::Result;

// Include the generated contract bindings
// The build script auto-detects contracts and generates bindings in src/bindings/
mod bindings;
pub mod deployer;
pub mod provider;
mod sol_types;

use provider::{HttpProviderWithWallet, TestProviderWithWallet, build_provider};
pub use sol_types::*;

/// Connect to a real blockchain, deploy the KeyManager contract, set the
/// `TIMEBOOST_KEY_MANAGER_MNEMONIC` as the manager.
/// Returns the (wallet provider, KeyManager address).
pub async fn init_chain(chain: Url) -> Result<(HttpProviderWithWallet, Address)> {
    dotenvy::dotenv()?;

    let mnemonic = dotenvy::var("TIMEBOOST_KEY_MANAGER_MNEMONIC")?;
    let account_idx = dotenvy::var("TIMEBOOST_KEY_ACCOUNT_INDEX")?.parse::<u32>()?;
    let provider = build_provider(mnemonic, account_idx, chain);

    let km_addr =
        deployer::deploy_key_manager_contract(&provider, provider.default_signer_address()).await?;

    Ok((provider, km_addr))
}

/// Similar to [`init_chain()`] but spawn a local test chain and deploy contracts there instead.
pub async fn init_test_chain() -> Result<(TestProviderWithWallet, Address)> {
    // this provider wraps both the test chain instance (exit on drop), and the wallet provider
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let km_addr =
        deployer::deploy_key_manager_contract(&provider, provider.default_signer_address()).await?;

    Ok((provider, km_addr))
}
