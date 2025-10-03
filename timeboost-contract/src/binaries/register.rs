//! CLI for registering next committee to KeyManager contract

use alloy::{
    consensus::crypto::secp256k1::public_key_to_address,
    primitives::Address,
    providers::{Provider, WalletProvider},
    signers::k256::ecdsa::VerifyingKey,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use reqwest::Client;
use std::path::PathBuf;
use std::time::Duration;
use timeboost_config::CommitteeConfig;
use timeboost_contract::{CommitteeMemberSol, KeyManager, provider::build_provider};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_utils::enc_key::ThresholdEncKeyCellAccumulator;
use timeboost_utils::types::logging;
use tracing::{info, warn};
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    #[clap(short, long)]
    mnemonic: String,

    #[clap(short, long, default_value_t = 0)]
    index: u32,

    #[clap(short, long)]
    url: Url,

    /// The contract address of deployed KeyManager.sol proxy
    #[clap(short, long)]
    key_manager_addr: Address,

    /// Path to the committee.toml config for the next committee
    #[clap(short, long)]
    config: PathBuf,

    /// What to register (new committee or threshold enc key?)
    #[clap(short, long)]
    action: Action,
}

/// Specific register action
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    /// register the next committee
    NewCommittee,
    /// register the threshold encryption key (when ready)
    ThresholdEncKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let args = Args::parse();

    let config = CommitteeConfig::read(&args.config)
        .await
        .context(format!("Failed to read config file: {:?}", &args.config))?;

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

    match args.action {
        Action::NewCommittee => {
            info!("Start committee registration");
            // prepare input argument from config file
            let members = config
                .members
                .iter()
                .map(|m| {
                    let pub_key = VerifyingKey::from_sec1_bytes(&m.signing_key.to_bytes())?;
                    Ok::<_, anyhow::Error>(CommitteeMemberSol {
                        sigKey: m.signing_key.to_bytes().into(),
                        dhKey: m.dh_key.as_bytes().into(),
                        dkgKey: m.dkg_enc_key.to_bytes()?.into(),
                        networkAddress: m.public_address.to_string(),
                        batchPosterAddress: m.public_address.to_string(),
                        sigKeyAddress: public_key_to_address(pub_key),
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
        }
        Action::ThresholdEncKey => {
            info!("Start threshold encryption key registration");
            let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
            let urls = config
                .members
                .iter()
                .map(|m| {
                    let addr = m.http_api.clone();
                    Url::parse(&format!("http://{addr}/v1/encryption-key"))
                        .with_context(|| format!("parsing {addr} into a url"))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mut acc = ThresholdEncKeyCellAccumulator::new(client, urls.into_iter());
            let Some(key) = acc.enc_key().await else {
                warn!("encryption key not available yet");
                return Err(anyhow!(
                    "threshold enc key not available on enough nodes, try later"
                ));
            };

            let _tx_receipt = contract
                .setThresholdEncryptionKey(key.to_owned().to_bytes()?.into())
                .send()
                .await?
                .get_receipt()
                .await?;
            assert_eq!(
                &ThresholdEncKey::from_bytes(&contract.thresholdEncryptionKey().call().await?.0)?,
                key
            );

            info!("Registered threshold encryption key");
        }
    }
    Ok(())
}
