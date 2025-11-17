use std::path::PathBuf;
use std::time::Duration;

use alloy::{
    consensus::crypto::secp256k1::public_key_to_address,
    providers::{Provider, WalletProvider},
    signers::k256::ecdsa::VerifyingKey,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use reqwest::Client;
use timeboost_config::{CommitteeDefinition, CommitteeMember, HTTP_API_PORT_OFFSET};
use timeboost_contract::{
    CommitteeMemberSol, KeyManager, deployer::deploy_key_manager_contract, provider::build_provider,
};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_utils::enc_key::ThresholdEncKeyCellAccumulator;
use url::Url;

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
enum Command {
    Deploy {
        #[arg(long)]
        index: u32,
        #[arg(long)]
        rpc_url: Url,
        #[arg(long)]
        mnemonic: String,
    },
    RegisterCommittee {
        #[arg(long)]
        index: u32,
        #[arg(long)]
        rpc_url: Url,
        #[arg(long)]
        contract: alloy::primitives::Address,
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        committee: PathBuf,
    },
    RegisterKey {
        #[arg(long)]
        index: u32,
        #[arg(long)]
        rpc_url: Url,
        #[arg(long)]
        contract: alloy::primitives::Address,
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        committee: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Command::parse() {
        Command::Deploy {
            index,
            rpc_url,
            mnemonic,
        } => {
            let provider = build_provider(mnemonic, index, rpc_url)?;
            let manager = provider.default_signer_address();
            println!("deploying with manager address: {manager:#x}");
            let addr = deploy_key_manager_contract(&provider, manager)
                .await
                .context("failed to deploy contract")?;
            println!("contract deployed at address: {addr:#x}");
        }
        Command::RegisterCommittee {
            index,
            rpc_url,
            contract,
            mnemonic,
            committee,
        } => {
            let definition = CommitteeDefinition::read(&committee).await?;
            let committee = definition.to_config().await?;
            let provider = build_provider(mnemonic, index, rpc_url)?;
            if provider.get_code_at(contract).await?.is_empty() {
                bail!("invalid contract address: {contract}");
            }
            let manager = KeyManager::new(contract, provider);
            let mut members = Vec::new();
            for member in committee.members {
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
                .setNextCommittee(committee.effective.into(), members)
                .send()
                .await?
                .get_receipt()
                .await?;

            println!("registered new committee");
        }
        Command::RegisterKey {
            index,
            rpc_url,
            contract,
            mnemonic,
            committee,
        } => {
            let committee = CommitteeDefinition::read(&committee).await?;
            let provider = build_provider(mnemonic, index, rpc_url)?;
            if provider.get_code_at(contract).await?.is_empty() {
                bail!("invalid key manager contract address: {contract}");
            }
            let manager = KeyManager::new(contract, provider);
            let mut urls = Vec::new();
            for m in committee.member {
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
