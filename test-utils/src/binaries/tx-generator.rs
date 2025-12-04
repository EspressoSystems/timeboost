use std::path::PathBuf;
use std::{str::FromStr, time::Duration};

use alloy::hex::ToHexExt;
use alloy::{
    consensus::{SignableTransaction, TxEnvelope, TxLegacy},
    network::{Ethereum, TransactionBuilder, TxSignerSync},
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rlp::Encodable,
    rpc::types::TransactionRequest,
    signers::local::{LocalSigner, PrivateKeySigner},
};
use anyhow::{Context, Result, bail, ensure};
use bon::Builder;
use bytes::BytesMut;
use clap::Parser;
use futures::future::join_all;
use reqwest::{Client, Url};
use serde::Serialize;
use timeboost::config::{ChainConfig, HTTP_API_PORT_OFFSET};
use timeboost::{
    config::CommitteeContract, crypto::prelude::ThresholdEncKey, types::BundleVariant,
};
use timeboost_contract::KeyManager;
use timeboost_types::{Auction, ChainId};
use timeboost_utils::load_generation::{
    TransactionVariant, TxInfo, make_bundle, make_dev_acct_bundle, make_dev_acct_txn, tps_to_millis,
};
use timeboost_utils::logging::init_logging;
use tokio::{
    signal::{
        ctrl_c,
        unix::{SignalKind, signal},
    },
    time::{interval, sleep},
};
use tracing::{debug, info, warn};

/// Private key from pre funded dev account on test node
/// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const DEV_ACCOUNT: &str = "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    chain: PathBuf,

    #[clap(long, default_value_t = 10101)]
    namespace: u64,

    #[clap(long, short)]
    express_lane: bool,

    #[clap(long, default_value_t = 100)]
    tps: u32,

    #[clap(long, default_value_t = 0.5)]
    enc_ratio: f64,

    #[clap(long, default_value_t = 0.5)]
    prio_ratio: f64,

    // Nitro Configuration
    #[clap(long, short)]
    nitro_url: Option<Url>,

    #[clap(long, short, default_value = DEV_ACCOUNT, requires = "nitro_url")]
    dev_account: String,

    #[clap(long, default_value_t = 5, requires = "nitro_url")]
    nitro_senders: u32,
}

#[derive(Debug, Clone)]
struct ApiUrl {
    regular_url: Url,
    priority_url: Url,
    eth_raw_url: Url,
    eth_enc_url: Url,
}

#[derive(Debug, Clone, Builder)]
struct TxGeneratorConfig {
    node_urls: Vec<ApiUrl>,
    tps: u32,
    enc_ratio: f64,
    prio_ratio: f64,
    chain_id: ChainId,
    parent_id: ChainId,
    parent_url: Url,
    auction_contract: Option<alloy::primitives::Address>,
    enc_key: ThresholdEncKey,
    nitro_cfg: Option<NitroConfig>,
}

#[derive(Debug, Clone, Builder)]
struct NitroConfig {
    rpc_url: Url,
    dev_account: String,
    senders: u32,
    bridge_addr: alloy::primitives::Address,
}

struct TxGenerator {
    node_urls: Vec<ApiUrl>,
    client: Client,
    interval: Duration,
    chain_id: ChainId,
    enc_ratio: f64,
    prio_ratio: f64,
    enc_key: ThresholdEncKey,
    auction: Option<Auction>,
    nitro: Option<(RootProvider, Vec<PrivateKeySigner>)>,
}

impl TxGenerator {
    pub(crate) async fn new(cfg: TxGeneratorConfig) -> Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        let nitro = if let Some(NitroConfig {
            rpc_url,
            dev_account,
            senders,
            bridge_addr,
        }) = cfg.nitro_cfg
        {
            let nitro_provider = RootProvider::<Ethereum>::connect(rpc_url.as_str()).await?;
            let l1_provider = RootProvider::<Ethereum>::connect(cfg.parent_url.as_str()).await?;
            let funded_keys: Vec<_> = {
                let sampled_keys: Vec<_> = (0..senders).map(|_| LocalSigner::random()).collect();
                let dev_key = PrivateKeySigner::from_str(&dev_account)?;
                if Self::fund_addresses(
                    &l1_provider,
                    &nitro_provider,
                    cfg.parent_id,
                    &dev_key,
                    &sampled_keys,
                    bridge_addr,
                )
                .await
                .is_ok()
                {
                    sampled_keys
                } else {
                    info!("bridging to senders failed; using dev account");
                    vec![PrivateKeySigner::from_str(&dev_account)?]
                }
            };
            Some((nitro_provider, funded_keys))
        } else {
            None
        };

        let auction = cfg.auction_contract.map(Auction::new);

        Ok(Self {
            node_urls: cfg.node_urls,
            interval: Duration::from_millis(tps_to_millis(cfg.tps)),
            client,
            chain_id: cfg.chain_id,
            enc_ratio: cfg.enc_ratio,
            prio_ratio: cfg.prio_ratio,
            nitro,
            auction,
            enc_key: cfg.enc_key,
        })
    }

    pub(crate) async fn generate(&self) -> Result<()> {
        if self.auction.is_some() {
            // priority bundle support
            self.generate_bundles().await
        } else {
            self.generate_raw_txs().await
        }
    }

    pub(crate) async fn generate_bundles(&self) -> Result<()> {
        info!("starting bundle generator");
        let mut interval = interval(self.interval);
        let auction = self.auction.as_ref().expect("auction is present");
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut count = 0;
        loop {
            let bundle = match &self.nitro {
                Some((p, senders)) => {
                    let len = senders.len();
                    let sender = senders[count % len].clone();
                    let receiver = senders[(count + 1) % len].clone();

                    let txn = match Self::prepare_txn(p, self.chain_id, sender, receiver.address())
                        .await
                    {
                        Ok(txn) => txn,
                        Err(_) => {
                            warn!("failed to prepare txn");
                            continue;
                        }
                    };

                    make_dev_acct_bundle(
                        &self.enc_key,
                        auction,
                        txn,
                        self.enc_ratio,
                        self.prio_ratio,
                    )
                    .map_err(|_| warn!("failed to generate dev account bundle"))
                    .ok()
                }
                None => make_bundle(self.chain_id, &self.enc_key, auction)
                    .map_err(|_| warn!("failed to generate bundle"))
                    .ok(),
            };
            let Some(b) = bundle else { continue };

            join_all(self.node_urls.iter().map(|urls| async {
                self.send_bundle(&b, &urls.regular_url, &urls.priority_url)
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

    pub(crate) async fn generate_raw_txs(&self) -> Result<()> {
        info!("starting tx-generator");
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut count = 0;
        loop {
            let tx = match &self.nitro {
                Some((p, senders)) => {
                    let len = senders.len();
                    let sender = senders[count % len].clone();
                    let receiver = senders[(count + 1) % len].clone();

                    let txn = match Self::prepare_txn(p, self.chain_id, sender, receiver.address())
                        .await
                    {
                        Ok(txn) => txn,
                        Err(_) => {
                            warn!("failed to prepare txn");
                            continue;
                        }
                    };

                    make_dev_acct_txn(&self.enc_key, txn, self.enc_ratio)
                        .map_err(|_| warn!("failed to generate dev account txn"))
                        .ok()
                }
                None => {
                    let dev_account = PrivateKeySigner::from_str(DEV_ACCOUNT)?;
                    let tx_info = TxInfo {
                        chain_id: self.chain_id.into(),
                        nonce: 0,
                        to: dev_account.address(),
                        base_fee: 5,
                        gas_limit: 5,
                        signer: dev_account,
                    };
                    make_dev_acct_txn(&self.enc_key, tx_info, self.enc_ratio)
                        .map_err(|_| warn!("failed to generate txn"))
                        .ok()
                }
            };

            let Some(tx) = tx else { continue };

            join_all(self.node_urls.iter().map(|urls| async {
                self.send_txn(tx.clone(), &urls.eth_raw_url, &urls.eth_enc_url)
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
        chain_id: ChainId,
        from: PrivateKeySigner,
        to: Address,
    ) -> Result<TxInfo> {
        let nonce = p.get_transaction_count(from.address()).await?;
        let tx = TransactionRequest::default()
            .with_chain_id(chain_id.into())
            .with_nonce(nonce)
            .with_from(from.address())
            .with_to(to)
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
            chain_id: chain_id.into(),
            nonce,
            to,
            gas_limit,
            base_fee,
            signer: from,
        })
    }

    async fn send_txn(&self, txn: TransactionVariant, raw_url: &Url, enc_url: &Url) {
        let result = match txn {
            TransactionVariant::PlainText(t) => {
                let raw_tx = RawTx { tx: t.encode_hex() };
                self.client.post(raw_url.clone()).json(&raw_tx).send().await
            }
            TransactionVariant::Encrypted(t) => {
                let enc_tx = EncTx {
                    chain_id: self.chain_id,
                    tx: t.encode_hex(),
                };
                self.client.post(enc_url.clone()).json(&enc_tx).send().await
            }
        };

        match result {
            Ok(response) => {
                if !response.status().is_success() {
                    warn!("response status: {}", response.status());
                }
            }
            Err(err) => {
                warn!(%err, "failed to send transaction");
            }
        }
    }

    async fn send_bundle(&self, bundle: &BundleVariant, regular_url: &Url, priority_url: &Url) {
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

    async fn fund_addresses(
        parent: &RootProvider,
        nitro: &RootProvider,
        chain_id: ChainId,
        dev_key: &PrivateKeySigner,
        keys: &[PrivateKeySigner],
        bridge_addr: alloy::primitives::Address,
    ) -> Result<()> {
        let mut failures = 0;
        let max = 40;
        let d = Duration::from_millis(100);
        for k in keys {
            loop {
                let Ok(nonce) = parent.get_transaction_count(dev_key.address()).await else {
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
                if let Err(err) = Self::fund_address(parent, chain_id, dev_key, k, nonce).await {
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
        chain_id: ChainId,
        from: &PrivateKeySigner,
        to: &PrivateKeySigner,
        nonce: u64,
    ) -> Result<()> {
        let one_eth_plus = U256::from_str("1100000000000000000").expect("1.1 ETH");
        let mut tx = TxLegacy {
            chain_id: Some(chain_id.into()),
            nonce,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: to.address().into(),
            value: one_eth_plus,
            input: alloy::primitives::Bytes::new(),
        };

        let sig = from.sign_transaction_sync(&mut tx)?;
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
        chain_id: ChainId,
        key: &PrivateKeySigner,
        bridge_addr: Address,
    ) -> Result<()> {
        let one_eth = U256::from_str("1000000000000000000").expect("1 ETH");

        // ABI encode depositEth() call
        let func_sig = alloy::hex::decode("439370b1")?;
        let calldata = alloy::primitives::Bytes::from(func_sig);

        let mut tx = TxLegacy {
            chain_id: Some(chain_id.into()),
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

#[derive(Serialize, Clone)]
struct RawTx {
    tx: String,
}

#[derive(Serialize, Clone)]
struct EncTx {
    chain_id: ChainId,
    tx: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();
    ensure!(
        0f64 <= args.enc_ratio && args.enc_ratio <= 1f64,
        "enc_ratio must be a fraction between 0 and 1"
    );
    ensure!(
        0f64 <= args.prio_ratio && args.prio_ratio <= 1f64,
        "prio_ratio must be a fraction between 0 and 1"
    );

    let mut chain_config = ChainConfig::read(&args.chain)
        .await
        .with_context(|| format!("could not read chain config {:?}", args.chain))?;

    if args.express_lane {
        if chain_config.auction_contract.is_none() {
            bail!("Failed to initialize express lane mode; missing auction contract")
        }
    } else {
        chain_config.auction_contract = None;
    }

    let mut contract = CommitteeContract::from(&chain_config);
    let Ok(committee) = contract.active().await else {
        bail!("no active committee on contract")
    };

    let mut urls = Vec::new();
    for m in committee.members {
        let addr = m.address.with_offset(HTTP_API_PORT_OFFSET);
        let regular_url = format!("http://{addr}/v1/submit/regular").parse()?;
        let priority_url = format!("http://{addr}/v1/submit/priority").parse()?;
        let eth_raw_url = format!("http://{addr}/v1/eth_sendRawTransaction").parse()?;
        let eth_enc_url = format!("http://{addr}/v1/eth_sendEncTransaction").parse()?;
        urls.push(ApiUrl {
            regular_url,
            priority_url,
            eth_raw_url,
            eth_enc_url,
        });
    }

    let provider = ProviderBuilder::new().connect_http(chain_config.rpc_url.clone());
    let contract = KeyManager::new(chain_config.key_management_contract, provider);
    let enc_key = ThresholdEncKey::from_bytes(&contract.thresholdEncryptionKey().call().await?.0)?;

    let nitro_cfg = args.nitro_url.map(|rpc_url| {
        NitroConfig::builder()
            .rpc_url(rpc_url)
            .dev_account(args.dev_account)
            .senders(args.nitro_senders)
            .bridge_addr(chain_config.inbox_contract)
            .build()
    });

    let config = TxGeneratorConfig::builder()
        .node_urls(urls)
        .tps(args.tps)
        .enc_ratio(args.enc_ratio)
        .prio_ratio(args.prio_ratio)
        .parent_url(chain_config.rpc_url)
        .parent_id(chain_config.id)
        .maybe_auction_contract(if args.express_lane {
            chain_config.auction_contract
        } else {
            None
        })
        .chain_id(args.namespace.into())
        .enc_key(enc_key)
        .maybe_nitro_cfg(nitro_cfg)
        .build();

    let tx_generator = TxGenerator::new(config).await?;

    let mut jh = tokio::spawn(async move { tx_generator.generate().await });

    let mut signal = signal(SignalKind::terminate()).expect("failed to create sigterm handler");
    tokio::select! {
        _ = ctrl_c() => {
            info!("received Ctrl+C, shutting down tx-generator...");
        },
        _ = signal.recv() => {
            info!("received sigterm, shutting down tx-generator...");
        },
        r = &mut jh => {
            warn!("tx-generator task was terminated, reason: {:?}", r);
        }
    }
    jh.abort();
    Ok(())
}
