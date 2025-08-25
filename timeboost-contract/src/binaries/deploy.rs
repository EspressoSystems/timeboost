//! CLI for contract deployment
//!
//! # Usage
//!
//! ```
//! # Write config to stdout
//! cargo run --bin deploy -- -m "your mnemonic here" -i 0 -u http://localhost:8545
//!
//! # Write config to a file
//! cargo run --bin deploy -- -m "your mnemonic here" -i 0 -u http://localhost:8545 -o output.toml
//! ```
//!
//! # Local test
//! Run `just test-contract-deploy`
use alloy::{primitives::Address, providers::WalletProvider};
use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;
use timeboost_contract::provider::build_provider;
use timeboost_utils::types::logging;
use tokio::fs;
use tracing::info;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    #[clap(short, long)]
    mnemonic: String,

    #[clap(short, long)]
    index: u32,

    #[clap(short, long)]
    url: Url,

    #[clap(short, long)]
    output: Option<PathBuf>,
}

/// Config type for the key manager who has the permission to update the KeyManager contract
/// See `test-configs/keymanager.toml` for an example
#[derive(Debug, Serialize)]
struct KeyManagerConfig {
    wallet: LocalWalletConfig,
    deployments: Deployments,
}

#[derive(Debug, Serialize)]
struct LocalWalletConfig {
    mnemonic: String,
    account_index: u32,
}

#[derive(Debug, Serialize)]
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

    info!("Starting contract deployment");

    // Construct the config from command-line arguments
    let mut cfg = KeyManagerConfig {
        wallet: LocalWalletConfig {
            mnemonic: args.mnemonic,
            account_index: args.index,
        },
        deployments: Deployments {
            chain_url: args.url,
            key_manager: None,
        },
    };

    // Build provider
    let provider = build_provider(
        cfg.wallet.mnemonic.clone(),
        cfg.wallet.account_index,
        cfg.deployments.chain_url.clone(),
    )?;

    let manager = provider.default_signer_address();
    info!("Deploying with manager address: {manager:#x}");

    // Deploy the KeyManager contract
    let km_addr = timeboost_contract::deployer::deploy_key_manager_contract(&provider, manager)
        .await
        .context("Failed to deploy KeyManager contract")?;
    info!("KeyManager deployed successfully at: {km_addr:#x}");

    // Update the address and deliver the final config
    cfg.deployments.key_manager = Some(km_addr);
    let toml = toml::to_string_pretty(&cfg)?;

    if let Some(out) = &args.output {
        fs::write(out, &toml).await?;
        info!(file=?out, "Config written to file");
    } else {
        println!("{toml}");
    }

    Ok(())
}
