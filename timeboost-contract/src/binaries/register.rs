//! CLI for registering next committee to KeyManager contract

use alloy::{
    primitives::Address,
    providers::{Provider, WalletProvider},
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;
use timeboost_contract::{CommitteeMemberSol, KeyManager, provider::build_provider};
use timeboost_utils::{keyset::CommitteeConfig, types::logging};
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

    /// The contract address of deployed KeyManager.sol proxy
    #[clap(short, long)]
    key_manager_addr: Address,

    /// Path to the committee.toml config for the next committee
    #[clap(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let args = Args::parse();

    let config = CommitteeConfig::read(&args.config)
        .await
        .context(format!("Failed to read config file: {:?}", &args.config))?;

    info!("Start committee registration");

    let provider = build_provider(args.mnemonic.clone(), args.index, args.url.clone())?;
    let addr = args.key_manager_addr;
    if provider
        .get_code_at(args.key_manager_addr)
        .await?
        .is_empty()
    {
        bail!("Invalid KeyManager contract address: {addr}, yet deployed or wrong chain!");
    }

    let manager = provider.default_signer_address();
    info!("Deploying with manager address: {manager:#x}");

    let contract = KeyManager::new(addr, provider);

    // prepare input argument from config file
    let members = config
        .members
        .iter()
        .map(|m| {
            Ok::<_, anyhow::Error>(CommitteeMemberSol {
                sigKey: m.signing_key.to_bytes().into(),
                dhKey: m.dh_key.as_bytes().into(),
                dkgKey: m.dkg_enc_key.to_bytes()?.into(),
                networkAddress: m.public_address.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let timestamp: u64 = config
        .effective_timestamp
        .as_second()
        .try_into()
        .with_context(|| {
            format!(
                "failed to convert timestamp {} to u64",
                config.effective_timestamp
            )
        })?;

    // send tx and invoke the contract
    let _tx_receipt = contract
        .setNextCommittee(timestamp, members)
        .send()
        .await?
        .get_receipt()
        .await?;

    let registered_cid = contract.nextCommitteeId().call().await? - 1;
    info!("Registered new committee with id: {registered_cid}");
    Ok(())
}
