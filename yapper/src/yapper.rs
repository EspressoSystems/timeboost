use std::{str::FromStr, time::Duration};

use alloy::{
    consensus::{SignableTransaction, TxEnvelope, TxLegacy},
    network::{Ethereum, TransactionBuilder, TxSignerSync},
    primitives::{Address, U256, address},
    providers::{Provider, RootProvider},
    rlp::Encodable,
    rpc::types::TransactionRequest,
    signers::local::{LocalSigner, PrivateKeySigner},
};
use anyhow::{Context, Result};
use bytes::BytesMut;
use futures::future::join_all;
use reqwest::{Client, Url};
use timeboost::{crypto::prelude::ThresholdEncKey, types::BundleVariant};
use timeboost_utils::{
    enc_key::ThresholdEncKeyCellAccumulator,
    load_generation::{TxInfo, make_bundle, make_dev_acct_bundle, tps_to_millis},
};
use tokio::time::{interval, sleep};
use tracing::{debug, info, trace, warn};

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

pub(crate) struct Yapper {
    urls: Vec<ApiUrls>,
    client: Client,
    interval: Duration,
    chain_id: u64,
    enc_ratio: f64,
    prio_ratio: f64,
    nitro: Option<(RootProvider, Vec<PrivateKeySigner>)>,
    enc_key: Option<ThresholdEncKey>,
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
        let nitro = if let Some(nitro_url) = cfg.nitro_url {
            let nitro_provider = RootProvider::<Ethereum>::connect(nitro_url.as_str()).await?;
            let l1_provider = RootProvider::<Ethereum>::connect(cfg.parent_url.as_str()).await?;
            let funded_keys: Vec<_> = {
                let sampled_keys: Vec<_> = (0..cfg.nitro_senders)
                    .map(|_| LocalSigner::random())
                    .collect();

                if Self::fund_addresses(
                    &l1_provider,
                    &nitro_provider,
                    cfg.parent_id,
                    &sampled_keys,
                    cfg.bridge_addr,
                )
                .await
                .is_ok()
                {
                    sampled_keys
                } else {
                    info!("bridging to senders failed; using dev account");
                    vec![PrivateKeySigner::from_str(DEV_ACCT_PRIV_KEY)?]
                }
            };
            Some((nitro_provider, funded_keys))
        } else {
            None
        };

        Ok(Self {
            urls,
            interval: Duration::from_millis(tps_to_millis(cfg.tps)),
            client,
            chain_id: cfg.chain_id,
            enc_ratio: cfg.enc_ratio,
            prio_ratio: cfg.prio_ratio,
            nitro,
            enc_key: cfg.threshold_enc_key,
        })
    }

    pub(crate) async fn yap(&self) -> Result<()> {
        info!("starting yapper");
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut acc = ThresholdEncKeyCellAccumulator::new(
            self.client.clone(),
            self.urls.iter().map(|url| url.enckey_url.clone()),
        );

        let mut count = 0;
        loop {
            let b = if let Some((ref p, ref senders)) = self.nitro {
                // For testing just send from the dev account to the validator address
                let sender = senders[count % senders.len()].clone();
                let Ok(txn) = Self::prepare_txn(p, sender, self.chain_id).await else {
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
                let Ok(b) = make_dev_acct_bundle(enc_key, txn, self.enc_ratio, self.prio_ratio)
                else {
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

            join_all(self.urls.iter().map(|urls| async {
                self.send_bundle_to_node(&b, &urls.regular_url, &urls.priority_url)
                    .await
            }))
            .await;
            if count % 100 == 0 {
                debug!("submitted: {} bundles", count);
            }
            count += 1;
            interval.tick().await;
        }
    }

    async fn prepare_txn(
        p: &RootProvider,
        from: PrivateKeySigner,
        chain_id: u64,
    ) -> Result<TxInfo> {
        let nonce = p.get_transaction_count(from.address()).await?;
        let tx = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce)
            .with_from(from.address())
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
            signer: from,
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
                trace!("sending rb with chain id: {:?}", bundle.chain_id());

                self.client
                    .post(regular_url.clone())
                    .json(&bundle)
                    .send()
                    .await
            }
            BundleVariant::Priority(signed_priority_bundle) => {
                trace!(
                    "sending pb with chain id: {:?}",
                    signed_priority_bundle.bundle().chain_id()
                );

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

    async fn fund_addresses(
        parent: &RootProvider,
        nitro: &RootProvider,
        chain_id: u64,
        keys: &[PrivateKeySigner],
        bridge_addr: Address,
    ) -> Result<()> {
        let mut failures = 0;
        let max = 40;
        let d = Duration::from_millis(100);
        for k in keys {
            loop {
                let Ok(nonce) = parent.get_transaction_count(DEV_ACCT_ADDRESS).await else {
                    failures += 1;
                    if failures == max {
                        warn!(addr=%k.address(), "failed to get nonce");
                        return Err(anyhow::anyhow!(
                            "max retries hit for key {}. falling back to dev acct only",
                            k.address()
                        ));
                    }

                    sleep(d).await;
                    continue;
                };
                if let Err(err) = Self::fund_address(parent, chain_id, k, nonce).await {
                    failures += 1;
                    if failures == max {
                        warn!(addr=%k.address(), %err, "failed to fund address");
                        return Err(anyhow::anyhow!(
                            "max retries hit for key {}. falling back to dev acct only",
                            k.address()
                        ));
                    }
                    sleep(d).await;
                    continue;
                }
                if let Err(err) = Self::bridge_funds(parent, chain_id, k, bridge_addr).await {
                    failures += 1;
                    if failures == max {
                        warn!(addr=%k.address(), %err, "failed to bridge funds");
                        return Err(anyhow::anyhow!(
                            "max retries hit for key {}. falling back to dev acct only",
                            k.address()
                        ));
                    }
                    sleep(d).await;
                    continue;
                }
                info!("bridged ETH to L2 for address {}", k.address());
                break;
            }
            failures = 0;
        }
        info!("waiting for funds to settle on L2");
        Self::wait_for_balances(nitro, keys).await?;
        Ok(())
    }

    async fn fund_address(
        p: &RootProvider,
        chain_id: u64,
        key: &PrivateKeySigner,
        nonce: u64,
    ) -> Result<()> {
        let to = key.address();
        let one_eth_plus = U256::from_str("1100000000000000000").expect("1.1 ETH");
        let mut tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: to.into(),
            value: one_eth_plus,
            input: alloy::primitives::Bytes::new(),
        };

        let dev_key = PrivateKeySigner::from_str(DEV_ACCT_PRIV_KEY)?;
        let sig = dev_key.sign_transaction_sync(&mut tx)?;
        let signed = tx.into_signed(sig);
        let env = TxEnvelope::Legacy(signed);
        let mut rlp = BytesMut::new();
        env.encode(&mut rlp);
        let raw_tx: bytes::Bytes = rlp.freeze();
        let _ = p.send_raw_transaction(&raw_tx).await?;
        Ok(())
    }

    async fn bridge_funds(
        p: &RootProvider,
        chain_id: u64,
        key: &PrivateKeySigner,
        bridge_addr: Address,
    ) -> Result<()> {
        let one_eth = U256::from_str("1000000000000000000").expect("1 ETH");

        // ABI encode depositEth() call
        let func_sig = alloy::hex::decode("439370b1")?;
        let calldata = alloy::primitives::Bytes::from(func_sig);

        let mut tx = TxLegacy {
            chain_id: Some(chain_id),
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 100_000,
            to: bridge_addr.into(),
            value: one_eth,
            input: calldata,
        };

        let sig = key.sign_transaction_sync(&mut tx)?;
        let signed = tx.into_signed(sig);
        let env = TxEnvelope::Legacy(signed);

        let mut rlp = BytesMut::new();
        env.encode(&mut rlp);
        let raw_tx: bytes::Bytes = rlp.freeze();
        let _ = p.send_raw_transaction(&raw_tx).await?;
        Ok(())
    }

    async fn wait_for_balances(p: &RootProvider, keys: &[PrivateKeySigner]) -> Result<()> {
        for _ in 0..10 {
            let mut all_non_zero = true;

            for key in keys.iter() {
                let balance = p.get_balance(key.address()).await.unwrap();
                if balance.is_zero() {
                    all_non_zero = false;
                    break;
                }
            }

            sleep(Duration::from_secs(5)).await;
            if all_non_zero {
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("unable to bridge funds"))
    }
}
