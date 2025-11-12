use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy::{
    consensus::crypto::secp256k1::public_key_to_address,
    providers::{Provider, WalletProvider},
    signers::k256::ecdsa::VerifyingKey,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use either::Either;
use multisig::CommitteeId;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use timeboost_config::{CommitteeMember, HTTP_API_PORT_OFFSET};
use timeboost_contract::{
    CommitteeMemberSol, KeyManager,
    deployer::deploy_key_manager_contract,
    provider::{HttpProviderWithWallet, build_provider},
};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_types::Timestamp;
use timeboost_utils::enc_key::ThresholdEncKeyCellAccumulator;
use tokio::fs;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    index: u32,
    rpc_url: Url,
    contract: alloy::primitives::Address,
    committee: Committee,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Committee {
    id: CommitteeId,
    #[serde(with = "either::serde_untagged")]
    start: Either<jiff::Timestamp, jiff::SignedDuration>,
    member: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Member {
    config: PathBuf,
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
enum Command {
    Deploy {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        menmonic: String,
    },
    RegisterCommittee {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        menmonic: String,
    },
    RegisterKey {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        menmonic: String,
    },
}

impl Config {
    async fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("could not read config: {:?}", path.as_ref()))?;

        let c: Self =
            toml::from_str(&s).with_context(|| format!("invalid config: {:?}", path.as_ref()))?;

        Ok(c)
    }

    fn provider(&self, mnemonic: String) -> Result<HttpProviderWithWallet> {
        let p = build_provider(mnemonic, self.index, self.rpc_url.clone())
            .context("failed to build provider")?;
        Ok(p)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Command::parse() {
        Command::Deploy { config, menmonic } => {
            let config = Config::read(config).await?;
            let provider = config.provider(menmonic)?;
            let manager = provider.default_signer_address();
            println!("deploying with manager address: {manager:#x}");
            let addr = deploy_key_manager_contract(&provider, manager)
                .await
                .context("failed to deploy contract")?;
            println!("contract deployed at address: {addr:#x}");
        }
        Command::RegisterCommittee { config, menmonic } => {
            let config = Config::read(config).await?;
            let provider = config.provider(menmonic)?;
            if provider.get_code_at(config.contract).await?.is_empty() {
                bail!("invalid contract address: {}", config.contract);
            }
            let manager = KeyManager::new(config.contract, provider);
            let effective = match config.committee.start {
                Either::Left(ts) => {
                    let s: u64 = ts.as_second().try_into().context("negative timestamp")?;
                    Timestamp::from(s)
                }
                Either::Right(d) => {
                    let s: u64 = d.as_secs().try_into().context("invalid duration")?;
                    Timestamp::now() + s
                }
            };

            let mut members = Vec::new();
            for m in config.committee.member {
                let member = CommitteeMember::read(&m.config).await?;
                let pubkey = VerifyingKey::from_sec1_bytes(&member.signing_key.to_bytes())?;
                let sol_member = CommitteeMemberSol {
                    sigKey: member.signing_key.to_bytes().into(),
                    dhKey: member.dh_key.as_bytes().into(),
                    dkgKey: member.dkg_enc_key.to_bytes()?.into(),
                    networkAddress: member.address.to_string(),
                    batchPosterAddress: member.batchposter.to_string(),
                    sigKeyAddress: public_key_to_address(pubkey),
                };
                members.push(sol_member)
            }

            let _receipt = manager
                .setNextCommittee(effective.into(), members)
                .send()
                .await?
                .get_receipt()
                .await?;

            println!("registered new committee");
        }
        Command::RegisterKey { config, menmonic } => {
            let config = Config::read(config).await?;
            let provider = config.provider(menmonic)?;
            if provider.get_code_at(config.contract).await?.is_empty() {
                bail!("invalid key manager contract address: {}", config.contract);
            }
            let manager = KeyManager::new(config.contract, provider);

            let mut urls = Vec::new();
            for m in config.committee.member {
                let member = CommitteeMember::read(&m.config).await?;
                let addr = member.address.with_offset(HTTP_API_PORT_OFFSET);
                let url = Url::parse(&format!("http://{addr}/v1/encryption-key"))
                    .with_context(|| format!("parsing {addr} into a url"))?;
                urls.push(url)
            }

            let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
            let mut acc = ThresholdEncKeyCellAccumulator::new(client, urls);
            let Some(key) = acc.enc_key().await else {
                bail!("threshold enc key not available on enough nodes")
            };

            let _receipt = manager
                .setThresholdEncryptionKey(key.to_owned().to_bytes()?.into())
                .send()
                .await?
                .get_receipt()
                .await?;

            assert_eq!(
                &ThresholdEncKey::from_bytes(&manager.thresholdEncryptionKey().call().await?.0)?,
                key
            );

            println!("registered threshold encryption key");
        }
    }

    Ok(())
}
