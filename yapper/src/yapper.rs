use std::{str::FromStr, time::Duration};

use alloy::{
    consensus::crypto::secp256k1::public_key_to_address, network::{Ethereum, TransactionBuilder}, primitives::{address, Address, U256}, providers::{Provider, RootProvider}, rpc::types::TransactionRequest, signers::{k256::{ecdsa::VerifyingKey}, local::PrivateKeySigner}
};
use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use reqwest::{Client, Url};
use timeboost::{crypto::prelude::ThresholdEncKey, types::BundleVariant};
use timeboost_utils::enc_key::ThresholdEncKeyCellAccumulator;
use timeboost_utils::load_generation::{TxInfo, make_bundle, make_dev_acct_bundle, tps_to_millis};
use tokio::time::interval;
use tracing::warn;
use secp256k1::rand::SeedableRng;

use crate::config::YapperConfig;

/// This is the address of the prefunded dev account for nitro chain
/// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const DEV_ACCT_ADDRESS: Address = address!("0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E");

/// Private key from pre funded dev account on test node
/// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const DEV_ACCT_PRIV_KEY: &str = "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// This is the address of validator for the chain
/// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const VALIDATOR_ADDRESS: Address = address!("0x6A568afe0f82d34759347bb36F14A6bB171d2CBe");

struct ApiUrls {
    regular_url: Url,
    priority_url: Url,
    enckey_url: Url,
}

#[derive(Clone)]
struct NitroAddress {
    kp: multisig::Keypair,
    address: alloy::primitives::Address,
}

pub(crate) struct Yapper {
    urls: Vec<ApiUrls>,
    client: Client,
    interval: Duration,
    chain_id: u64,
    provider: Option<RootProvider>,
    enc_key: Option<ThresholdEncKey>,
    addresses: Vec<NitroAddress>,
}

impl Yapper {
    pub(crate) async fn new(cfg: YapperConfig) -> Result<Self> {
        let mut urls = Vec::new();

        for addr in cfg.addresses {
            let regular_url = Url::parse(&format!("http://{addr}/v1/submit/regular"))
                .with_context(|| format!("parsing {addr} into a url"))?;
            let priority_url = Url::parse(&format!("http://{addr}/v1/submit/priority"))
                .with_context(|| format!("parsing {addr} into a url"))?;
            let enckey_url = Url::parse(&format!("http://{addr}/v1/encryption-key"))
                .with_context(|| format!("parsing {addr} into a url"))?;

            urls.push(ApiUrls {
                regular_url,
                priority_url,
                enckey_url,
            });
        }
        
        
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        
        let (provider, addresses) = if let Some(url) = cfg.nitro_url {
            let mut addresses = vec![];
            let mut s_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(rand::random());
            for _ in 0..=100 {
                let kp = multisig::Keypair::generate_with_rng(&mut s_rng);
                let pub_key = VerifyingKey::from_sec1_bytes(&kp.public_key().to_bytes())?;
                addresses.push(
                    NitroAddress {
                        kp,
                        address: public_key_to_address(pub_key)
                    }
                )
            }
            (Some(RootProvider::<Ethereum>::connect(url.as_str()).await?), addresses)
        } else {
            (None, vec![])
        };

        Ok(Self {
            urls,
            interval: Duration::from_millis(tps_to_millis(cfg.tps)),
            client,
            provider,
            chain_id: cfg.chain_id,
            enc_key: cfg.threshold_enc_key,
            addresses,
        })
    }

    pub(crate) async fn yap(&self) -> Result<()> {
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut acc = ThresholdEncKeyCellAccumulator::new(
            self.client.clone(),
            self.urls.iter().map(|url| url.enckey_url.clone()),
        );

        let mut count: u64 = 0;
        loop {
            let b = if let Some(ref p) = self.provider {
                // For testing just send from the dev account to the validator address
                let Ok(txn) = Self::prepare_txn(p, self.chain_id, &self.addresses[count as usize % self.addresses.len()]).await else {
                    warn!("failed to prepare txn");
                    continue;
                };
                let enc_key = match self.enc_key.as_ref() {
                    Some(key) => key,
                    None => match acc.enc_key().await {
                        Some(key) => key,
                        None => {
                            warn!("encryption key not available yet");
                            continue;
                        }
                    },
                };
                let Ok(b) = make_dev_acct_bundle(enc_key, txn) else {
                    warn!("failed to generate dev account bundle");
                    continue;
                };
                b
            } else {
                let enc_key = match self.enc_key.as_ref() {
                    Some(key) => key,
                    None => match acc.enc_key().await {
                        Some(key) => key,
                        None => {
                            warn!("encryption key not available yet");
                            continue;
                        }
                    },
                };
                let Ok(b) = make_bundle(enc_key) else {
                    warn!("failed to generate bundle");
                    continue;
                };
                b
            };

            let r = join_all(self.urls.iter().map(|urls| async {
                self.send_bundle_to_node(&b, &urls.regular_url, &urls.priority_url)
                    .await
            }))
            .await;
            if r.iter().any(|l| l.is_ok()) {
                count += 1;
                if count % 100 == 0 {
                    tracing::error!("yapper count: {}", count);
                }
                
                if count == 10000 {
                    tracing::error!("yapper donezel");
                    return Ok(());
                }
            }

            interval.tick().await;
        }
    }

    async fn prepare_txn(p: &RootProvider, chain_id: u64, next_sender: &NitroAddress) -> Result<TxInfo> {
        let mut value = U256::from(1);
        let mut to = VALIDATOR_ADDRESS;
        let mut signer = PrivateKeySigner::from_str(DEV_ACCT_PRIV_KEY)?;
        let mut from = DEV_ACCT_ADDRESS;
        let balance: U256 = p.get_balance(next_sender.address).await?;
        if balance.is_zero() {
            value = U256::from(99999999999999999 as u64);
            to = next_sender.address;
        } else {
            signer = PrivateKeySigner::from_slice(&next_sender.kp.secret_key().as_slice())?;
            from = next_sender.address;
        }
        let nonce = p.get_transaction_count(from).await?;
        let tx = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce)
            .with_from(from)
            // Just choosing an address that already exists on the chain
            .with_to(to)
            .with_value(value);

        let gas_limit = p
            .estimate_gas(tx)
            .await
            .with_context(|| "failed to estimate gas")?;

        let base_fee = p
            .get_gas_price()
            .await
            .with_context(|| "failed to get gas price")?;

        Ok(TxInfo {
            chain_id,
            nonce,
            to,
            gas_limit,
            base_fee,
            signer,
            value,
        })
    }

    async fn send_bundle_to_node(
        &self,
        bundle: &BundleVariant,
        regular_url: &Url,
        priority_url: &Url,
    ) -> Result<()> {
        let result = match bundle {
            BundleVariant::Regular(bundle) => {
                self.client
                    .post(regular_url.clone())
                    .json(&bundle)
                    .send()
                    .await
            }
            BundleVariant::Priority(signed_priority_bundle) => {
                self.client
                    .post(priority_url.clone())
                    .json(&signed_priority_bundle)
                    .send()
                    .await
            }
            _ => {
                warn!("Unsupported bundle variant");
                return Err(anyhow!("err"));
            }
        };

        match result {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("response status: {}", response.status());
                    return Err(anyhow!("err"));
                }
                return Ok(());
            }
            Err(err) => {
                warn!(%err, "failed to send bundle");
                return Err(anyhow!("err"));
            }
        }
    }
}
