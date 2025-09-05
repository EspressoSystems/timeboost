//! Timeboost Contract Bindings, Deployer and API bridges.
//!
//! This crate provides Rust bindings and API to interact with smart contracts,

use alloy::{
    primitives::Address,
    providers::{ProviderBuilder, WalletProvider},
};
use anyhow::Result;

// Include the generated contract bindings
// The build script auto-detects contracts and generates bindings in src/bindings/
mod bindings;
pub mod committee;
pub mod deployer;
pub mod events;
pub mod provider;
mod sol_types;

pub use committee::*;
pub use events::*;
pub use sol_types::*;
use timeboost_types::TestProviderWithWallet;

/// Spawn a local test blockchain and deploy KeyManager contract.
/// Returns a WalletProvider to the chain and the deployed contract address.
pub async fn init_test_chain() -> Result<(TestProviderWithWallet, Address)> {
    // this provider wraps both the test chain instance (exit on drop), and the wallet provider
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let km_addr =
        deployer::deploy_key_manager_contract(&provider, provider.default_signer_address()).await?;

    Ok((provider, km_addr))
}
