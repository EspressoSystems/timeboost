//! CLI for contract deployment
//!
//! # Local test
//! Run `just test-contract-deploy`
use alloy::{primitives::Address, providers::WalletProvider};
use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::{fs, path::PathBuf};
use timeboost_contract::provider::build_provider;
use timeboost_utils::types::logging;
use toml_edit::{DocumentMut, value};
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// Config file storing `KeyManagerConfig`
    #[clap(short, long, default_value = "./test-configs/keymanager.toml")]
    config: PathBuf,
}

/// Config type for the key manager who has the permission to update the KeyManager contract
/// See `test-configs/keymanager.toml` for an example
#[derive(Debug, Deserialize)]
struct KeyManagerConfig {
    wallet: LocalWalletConfig,
    deployments: Deployments,
}

#[derive(Debug, Deserialize)]
struct LocalWalletConfig {
    mnemonic: String,
    account_index: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Deployments {
    /// RPC endpoint of the target chain
    chain_url: Url,
    /// The contract address of KeyManager.sol proxy
    key_manager: Option<Address>,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let args = Args::parse();
    let config_path = args.config;

    tracing::info!(
        "Starting contract deployment with config: {:?}",
        config_path
    );

    // Read and parse config file
    let config_content = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {config_path:?}"))?;
    let config: KeyManagerConfig = toml::from_str(&config_content)
        .with_context(|| format!("Failed to parse config file: {config_path:?}"))?;
    tracing::info!("Config loaded successfully");

    // Build provider
    let provider = build_provider(
        config.wallet.mnemonic,
        config.wallet.account_index,
        config.deployments.chain_url,
    );

    let manager = provider.default_signer_address();
    tracing::info!("Deploying with maanger address: {manager:#x}");

    // Deploy the KeyManager contract
    let km_addr = timeboost_contract::deployer::deploy_key_manager_contract(&provider, manager)
        .await
        .context("Failed to deploy KeyManager contract")?;
    tracing::info!("KeyManager deployed successfully at: {km_addr:#x}");

    // Update the config file with the deployed address
    let mut doc = config_content
        .parse::<DocumentMut>()
        .with_context(|| format!("Failed to parse TOML in config file: {config_path:?}"))?;

    // Set the key_manager address in the deployments section
    doc["deployments"]["key_manager"] = value(format!("{km_addr:#x}"));

    // Write back to file
    fs::write(&config_path, doc.to_string())
        .with_context(|| format!("Failed to write updated config file: {config_path:?}"))?;

    tracing::info!("Config file updated with KeyManager address: {km_addr:#x}");

    Ok(())
}
