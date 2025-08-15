use std::{str::FromStr, time::Duration};

use alloy::{
    network::{Ethereum, TransactionBuilder},
    primitives::{Address, U256, address},
    providers::{Provider, RootProvider},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result};
use futures::future::join_all;
use reqwest::{Client, Url};
use timeboost::types::BundleVariant;
use timeboost_utils::load_generation::{TxInfo, make_bundle, make_dev_acct_bundle, tps_to_millis};
use tokio::time::interval;
use tracing::warn;

use crate::{config::YapperConfig, enc_key::ThresholdEncKeyCellAccumulator};

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

pub(crate) struct Yapper {
    urls: Vec<ApiUrls>,
    client: Client,
    interval: Duration,
    chain_id: u64,
    provider: Option<RootProvider>,
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
        let provider = if cfg.nitro_integration {
            Some(RootProvider::<Ethereum>::connect(&cfg.nitro_url).await?)
        } else {
            None
        };
        Ok(Self {
            urls,
            interval: Duration::from_millis(tps_to_millis(cfg.tps)),
            client,
            provider,
            chain_id: cfg.chain_id,
        })
    }

    pub(crate) async fn yap(&self) -> Result<()> {
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut acc = ThresholdEncKeyCellAccumulator::new(
            self.client.clone(),
            self.urls.iter().map(|url| url.enckey_url.clone()),
        );

        loop {
            let b = if let Some(ref p) = self.provider {
                // For testing just send from the dev account to the validator address
                let Ok(txn) = Self::prepare_txn(p, self.chain_id).await else {
                    warn!("failed to prepare txn");
                    continue;
                };
                let Ok(b) = make_dev_acct_bundle(acc.enc_key().await, txn) else {
                    warn!("failed to generate dev account bundle");
                    continue;
                };
                b
            } else {
                let Ok(b) = make_bundle(acc.enc_key().await) else {
                    warn!("failed to generate bundle");
                    continue;
                };
                b
            };

            join_all(self.urls.iter().map(|urls| async {
                self.send_bundle_to_node(&b, &urls.regular_url, &urls.priority_url)
                    .await
            }))
            .await;

            interval.tick().await;
        }
    }

    async fn prepare_txn(p: &RootProvider, chain_id: u64) -> Result<TxInfo> {
        let nonce = p.get_transaction_count(DEV_ACCT_ADDRESS).await?;
        let tx = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce)
            .with_from(DEV_ACCT_ADDRESS)
            // Just choosing an address that already exists on the chain
            .with_to(VALIDATOR_ADDRESS)
            .with_value(U256::from(1));

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
            to: VALIDATOR_ADDRESS,
            gas_limit,
            base_fee,
            signer: PrivateKeySigner::from_str(DEV_ACCT_PRIV_KEY)?,
        })
    }

    async fn send_bundle_to_node(
        &self,
        bundle: &BundleVariant,
        regular_url: &Url,
        priority_url: &Url,
    ) {
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
                return;
            }
        };

        match result {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("response status: {}", response.status());
                }
            }
            Err(err) => {
                warn!(%err, "failed to send bundle");
            }
        }
    }
}
