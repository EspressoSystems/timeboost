use std::time::Duration;

use alloy::{
    network::{Ethereum, TransactionBuilder},
    primitives::{Address, U256, address},
    providers::{Provider, RootProvider},
    rpc::types::TransactionRequest,
};
use anyhow::{Context, Result};
use futures::future::join_all;
use reqwest::{Client, Url};
use timeboost::types::BundleVariant;
use timeboost_utils::load_generation::{make_bundle, make_dev_acct_bundle, tps_to_millis};
use tokio::time::interval;
use tracing::warn;

use crate::{config::YapperConfig, enc_key::ThresholdEncKeyCellAccumulator};

/// This is the address of the prefunded dev account for nitro chain
/// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const DEV_ACCT_ADDRESS: Address = address!("0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E");

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
    provider: Option<RootProvider>,
    txn_limit: Option<u64>,
}

impl Yapper {
    pub(crate) async fn new(config: YapperConfig) -> Result<Self> {
        let mut urls = Vec::new();

        for addr in config.addresses {
            let regular_url = Url::parse(&format!("http://{addr}/v0/submit-regular"))
                .with_context(|| format!("parsing {addr} into a url"))?;
            let priority_url = Url::parse(&format!("http://{addr}/v0/submit-priority"))
                .with_context(|| format!("parsing {addr} into a url"))?;
            let enckey_url = Url::parse(&format!("http://{addr}/v0/enckey"))
                .with_context(|| format!("parsing {addr} into a url"))?;

            urls.push(ApiUrls {
                regular_url,
                priority_url,
                enckey_url,
            });
        }
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        let (provider, interval, txn_limit) = if config.nitro_integration {
            (
                Some(RootProvider::<Ethereum>::connect(&config.nitro_url).await?),
                Duration::from_secs(1),
                // For nitro running in ci, avoid race conditions with block height by setting txn
                // limit
                Some(config.txn_limit),
            )
        } else {
            (None, Duration::from_millis(tps_to_millis(config.tps)), None)
        };
        Ok(Self {
            urls,
            interval,
            client,
            provider,
            txn_limit,
        })
    }

    pub(crate) async fn yap(&self) -> Result<()> {
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut acc = ThresholdEncKeyCellAccumulator::new(
            self.client.clone(),
            self.urls.iter().map(|url| url.enckey_url.clone()),
        );

        let mut txn_sent = 0;
        loop {
            let b = if let Some(ref p) = self.provider {
                let nonce = p.get_transaction_count(DEV_ACCT_ADDRESS).await?;
                // Chain id from l2 chain
                // https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
                let chain_id = 412346;
                let tx = TransactionRequest::default()
                    .with_chain_id(chain_id)
                    .with_nonce(nonce)
                    .with_from(DEV_ACCT_ADDRESS)
                    .with_to(VALIDATOR_ADDRESS)
                    .with_value(U256::from(1));

                let Ok(estimate) = p.estimate_gas(tx).await else {
                    warn!("failed to get estimate");
                    continue;
                };
                let Ok(price) = p.get_gas_price().await else {
                    warn!("failed to get gas price");
                    continue;
                };
                // For testing just send from the dev account to the validator address
                let Ok(b) = make_dev_acct_bundle(
                    acc.enc_key().await,
                    chain_id,
                    nonce,
                    VALIDATOR_ADDRESS,
                    estimate,
                    price,
                ) else {
                    warn!("failed to generate dev account bundle");
                    continue;
                };
                b
            } else {
                // create a bundle for next `interval.tick()`, then send this bundle to each node
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
            txn_sent += 1;
            if self.txn_limit == Some(txn_sent) {
                warn!("hit txn limit, terminating yapper");
                return Ok(());
            }

            interval.tick().await;
        }
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
