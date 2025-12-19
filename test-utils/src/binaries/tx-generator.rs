use std::path::PathBuf;
use std::{str::FromStr, time::Duration};

use alloy::network::Ethereum;
use alloy::{
    hex::ToHexExt,
    providers::{ProviderBuilder, RootProvider},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result, bail, ensure};
use bon::Builder;
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
    TransactionVariant, create_bundle, create_tx, prepare, prepare_test, tps_to_millis,
};
use timeboost_utils::logging::init_logging;
use tokio::{
    signal::{
        ctrl_c,
        unix::{SignalKind, signal},
    },
    time::interval,
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    chain: PathBuf,

    #[clap(long, default_value_t = 10101)]
    namespace: u64,

    #[clap(long, default_value_t = 100.0)]
    tps: f64,

    #[clap(long, default_value_t = 0.5)]
    enc_ratio: f64,

    #[clap(long, default_value_t = 0.5)]
    prio_ratio: f64,

    #[clap(
        long,
        use_value_delimiter = true,
        default_value = "0x4a7347a749f03f485414757fce2ee0c77a76ee0a019c8af32b034b3b240a3136"
    )]
    signers: Vec<String>,

    #[clap(long, default_value_t = false)]
    nitro: bool,
}

#[derive(Debug, Clone)]
struct ApiUrl {
    regular_url: Url,
    priority_url: Url,
    json_rpc_url: Url,
}

#[derive(Debug, Clone, Builder)]
struct TxGeneratorConfig {
    node_urls: Vec<ApiUrl>,
    tps: f64,
    enc_ratio: f64,
    prio_ratio: f64,
    chain_id: ChainId,
    enc_key: Option<ThresholdEncKey>,
    signers: Vec<PrivateKeySigner>,
    auction_contract: Option<alloy::primitives::Address>,
    nitro: bool,
}

struct TxGenerator {
    node_urls: Vec<ApiUrl>,
    client: Client,
    tps: f64,
    chain_id: ChainId,
    enc_ratio: f64,
    prio_ratio: f64,
    enc_key: Option<ThresholdEncKey>,
    signers: Vec<PrivateKeySigner>,
    auction: Option<Auction>,
    nitro: bool,
}

impl TxGenerator {
    pub(crate) async fn new(cfg: TxGeneratorConfig) -> Result<Self> {
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        let auction = cfg.auction_contract.map(Auction::new);

        Ok(Self {
            node_urls: cfg.node_urls,
            client,
            chain_id: cfg.chain_id,
            tps: cfg.tps,
            enc_ratio: cfg.enc_ratio,
            prio_ratio: cfg.prio_ratio,
            enc_key: cfg.enc_key,
            signers: cfg.signers,
            nitro: cfg.nitro,
            auction,
        })
    }

    pub(crate) async fn generate(&self) -> Result<()> {
        if self.auction.is_some() {
            self.generate_bundles().await
        } else {
            self.generate_raw_txs().await
        }
    }

    pub(crate) async fn generate_bundles(&self) -> Result<()> {
        info!(
            "Starting with type={}, tps={}, enc_ratio={}, prio_ratio={}, nitro={}",
            "bundle", self.tps, self.enc_ratio, self.prio_ratio, self.nitro
        );
        let duration = Duration::from_millis(tps_to_millis(self.tps));
        let mut interval = interval(duration);
        let p = RootProvider::<Ethereum>::connect(self.node_urls[0].json_rpc_url.as_str()).await?;
        let auction = self.auction.as_ref().expect("auction is present");
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut count = 0;
        loop {
            let len = self.signers.len();
            let sender = self.signers[count % len].clone();
            let receiver = self.signers[(count + 1) % len].clone();

            let tx = if self.nitro {
                match prepare(&p, self.chain_id, sender, receiver.address()).await {
                    Ok(tx) => tx,
                    Err(err) => {
                        warn!(%err, "failed to prepare bundle txn");
                        continue;
                    }
                }
            } else {
                prepare_test(self.chain_id, sender, receiver.address())
            };

            let bundle = create_bundle(
                self.enc_key.as_ref(),
                auction,
                tx,
                self.enc_ratio,
                self.prio_ratio,
            )
            .map_err(|_| warn!("failed to generate dev account bundle"))
            .ok();
            let Some(b) = bundle else { continue };

            join_all(self.node_urls.iter().map(|urls| async {
                self.send_bundle(&b, &urls.regular_url, &urls.priority_url)
                    .await
            }))
            .await;

            count += 1;
            interval.tick().await;
        }
    }

    pub(crate) async fn generate_raw_txs(&self) -> Result<()> {
        info!(
            "Starting with type={}, tps={}, enc_ratio={}, prio_ratio={}, nitro={}",
            "raw-tx", self.tps, self.enc_ratio, self.prio_ratio, self.nitro
        );
        let duration = Duration::from_millis(tps_to_millis(self.tps));
        let mut interval = interval(duration);
        let p = RootProvider::<Ethereum>::connect(self.node_urls[0].json_rpc_url.as_str()).await?;
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut count = 0;
        loop {
            let len = self.signers.len();
            let sender = self.signers[count % len].clone();
            let receiver = self.signers[(count + 1) % len].clone();

            let tx = if self.nitro {
                match prepare(&p, self.chain_id, sender, receiver.address()).await {
                    Ok(tx) => tx,
                    Err(err) => {
                        warn!(%err, "failed to prepare raw txn");
                        continue;
                    }
                }
            } else {
                prepare_test(self.chain_id, sender, receiver.address())
            };

            let tx = create_tx(self.enc_key.as_ref(), tx, self.enc_ratio)
                .map_err(|_| warn!("failed to generate dev account txn"))
                .ok();

            let Some(tx) = tx else { continue };

            join_all(
                self.node_urls
                    .iter()
                    .map(|urls| async { self.send_tx(tx.clone(), &urls.json_rpc_url).await }),
            )
            .await;

            count += 1;
            interval.tick().await;
        }
    }

    async fn send_tx(&self, txn: TransactionVariant, url: &Url) {
        let (method, params) = match txn {
            TransactionVariant::PlainText(t) => {
                ("eth_sendRawTransaction", vec![t.encode_hex_with_prefix()])
            }
            TransactionVariant::Encrypted(t) => {
                let chain_id: u64 = self.chain_id.into();
                (
                    "eth_sendEncTransaction",
                    vec![t.encode_hex_with_prefix(), chain_id.to_string()],
                )
            }
        };

        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: 1,
        };

        let result = self.client.post(url.clone()).json(&req).send().await;

        match result {
            Ok(response) if !response.status().is_success() => {
                warn!("response status: {}", response.status());
            }
            Err(err) => {
                warn!(%err, "failed to send transaction");
            }
            _ => {}
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
}

#[derive(Serialize, Clone)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<String>,
    id: u64,
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
    ensure!(
        !args.signers.is_empty(),
        "must have at least one signer key"
    );

    let chain_config = ChainConfig::read(&args.chain)
        .await
        .with_context(|| format!("could not read chain config {:?}", args.chain))?;

    let mut contract = CommitteeContract::from(&chain_config);
    let Ok(committee) = contract.active().await else {
        bail!("no active committee on contract")
    };

    let signers = args
        .signers
        .into_iter()
        .map(|k| PrivateKeySigner::from_str(&k))
        .collect::<Result<Vec<_>, _>>()?;

    let mut urls = Vec::new();
    for m in committee.members {
        let addr = m.address.with_offset(HTTP_API_PORT_OFFSET);
        let regular_url = format!("http://{addr}/v1/submit/regular").parse()?;
        let priority_url = format!("http://{addr}/v1/submit/priority").parse()?;
        let json_rpc_url = format!("http://{addr}/v1/").parse()?;
        urls.push(ApiUrl {
            regular_url,
            priority_url,
            json_rpc_url,
        });
    }

    let enc_key = if args.enc_ratio == 0f64 {
        None
    } else {
        let provider = ProviderBuilder::new().connect_http(chain_config.rpc_url.clone());
        let contract = KeyManager::new(chain_config.key_management_contract, provider);
        Some(ThresholdEncKey::from_bytes(
            &contract.thresholdEncryptionKey().call().await?.0,
        )?)
    };

    let config = TxGeneratorConfig::builder()
        .node_urls(urls)
        .tps(args.tps)
        .enc_ratio(args.enc_ratio)
        .prio_ratio(args.prio_ratio)
        .maybe_auction_contract(chain_config.auction_contract)
        .chain_id(args.namespace.into())
        .maybe_enc_key(enc_key)
        .signers(signers)
        .nitro(args.nitro)
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
