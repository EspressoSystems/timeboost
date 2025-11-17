use std::path::Path;
use std::time::Duration;
use std::{collections::HashSet, path::PathBuf};

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
use timeboost_config::{
    CommitteeDefinitions, CommitteeFile, CommitteeMember, HTTP_API_PORT_OFFSET,
};
use timeboost_contract::{
    CommitteeMemberSol, KeyManager, deployer::deploy_key_manager_contract, provider::build_provider,
};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_types::Timestamp;
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
        id: CommitteeId,
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
        id: CommitteeId,
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
            id,
            index,
            rpc_url,
            contract,
            mnemonic,
            committee,
        } => {
            let config = CommitteeDefinitions::read(&committee).await?;
            let committee = get_committee(&committee, id, config)?;
            let provider = build_provider(mnemonic, index, rpc_url)?;
            if provider.get_code_at(contract).await?.is_empty() {
                bail!("invalid contract address: {contract}");
            }
            let manager = KeyManager::new(contract, provider);

            let effective = match committee.start {
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
            for m in committee.member {
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
        Command::RegisterKey {
            id,
            index,
            rpc_url,
            contract,
            mnemonic,
            committee,
        } => {
            let config = CommitteeDefinitions::read(&committee).await?;
            let committee = get_committee(&committee, id, config)?;
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

fn get_committee<P>(path: P, id: CommitteeId, config: CommitteeDefinitions) -> Result<CommitteeFile>
where
    P: AsRef<Path>,
{
    let set: HashSet<CommitteeId> = HashSet::from_iter(config.committee.iter().map(|c| c.id));
    if set.len() != config.committee.len() {
        bail!("duplicate committee ids in {:?}", path.as_ref())
    }
    let Some(committee) = config.committee.into_iter().find(|c| c.id == id) else {
        bail!("no committee with id {id}")
    };
    Ok(committee)
}
