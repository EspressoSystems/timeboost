use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{str::FromStr, time::Duration};

use alloy::network::Ethereum;
use alloy::rpc::client::RpcClient;
use alloy::{
    hex::ToHexExt,
    providers::{ProviderBuilder, RootProvider},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, Result, bail, ensure};
use bon::Builder;
use clap::Parser;
use futures::StreamExt;
use futures::future::join_all;
use futures::stream::BoxStream;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Url};
use serde::Serialize;
use timeboost::config::{ChainConfig, CommitteeConfig, CommitteeContract, HTTP_API_PORT_OFFSET};
use timeboost::{crypto::prelude::ThresholdEncKey, types::BundleVariant};
use timeboost_contract::KeyManager;
use timeboost_types::{Auction, ChainId};
use timeboost_utils::load_generation::{
    TransactionVariant, create_bundle, create_tx, prepare, prepare_test, tps_to_millis,
};
use timeboost_utils::logging::init_logging;
use tokio::time::{Instant, sleep_until};
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

    #[clap(long)]
    apikey: Option<String>,
}

#[derive(Debug, Clone)]
struct ApiUrl {
    regular_url: Url,
    priority_url: Url,
    json_rpc_url: Url,
}

#[derive(Debug, Clone, Builder)]
struct TxGeneratorConfig {
    tps: f64,
    enc_ratio: f64,
    prio_ratio: f64,
    chain_id: ChainId,
    enc_key: Option<ThresholdEncKey>,
    signers: Vec<PrivateKeySigner>,
    nitro: bool,
    apikey: Option<String>,
}

struct TxGeneratorState {
    current: CommitteeConfig,
    next: Option<(Instant, CommitteeConfig)>,
    provider: RootProvider,
    node_urls: Vec<ApiUrl>,
}

enum SubmissionStrategy {
    Bundle(Auction),
    RawTx,
}

struct TxGenerator {
    config: TxGeneratorConfig,
    state: TxGeneratorState,
    client: Client,
    strategy: SubmissionStrategy,
}

impl TxGenerator {
    pub(crate) async fn new(
        cfg: TxGeneratorConfig,
        current: CommitteeConfig,
        auction: Option<Auction>,
    ) -> Result<Self> {
        let client = build_client(cfg.apikey.as_deref())?;
        let node_urls = urls_from_config(&current)?;
        let provider = build_provider(&node_urls[0].json_rpc_url, cfg.apikey.as_deref()).await?;

        let strategy = match auction {
            Some(auction) => SubmissionStrategy::Bundle(auction),
            None => SubmissionStrategy::RawTx,
        };

        let state = TxGeneratorState {
            current,
            next: None,
            provider,
            node_urls,
        };

        Ok(Self {
            config: cfg,
            state,
            client,
            strategy,
        })
    }

    pub(crate) async fn generate(
        mut self,
        mut committees: BoxStream<'static, CommitteeConfig>,
    ) -> Result<()> {
        let is_bundle = matches!(self.strategy, SubmissionStrategy::Bundle(_));

        info!(
            type       = if is_bundle { "bundle" } else { "raw-tx" },
            tps        = %self.config.tps,
            enc_ratio  = %self.config.enc_ratio,
            prio_ratio = %self.config.prio_ratio,
            nitro      = %self.config.nitro,
            "Starting"
        );

        let mut interval = interval(Duration::from_millis(tps_to_millis(self.config.tps)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut count = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(err) = self.submit(count).await {
                        warn!(
                            error = %err,
                            committee = %self.state.current.id,
                            "failed to submit tx"
                        );
                    } else {
                        count += 1;
                    }
                },
                Some(committee) = committees.next() => {
                    let deadline = unix_to_instant(committee.effective.into());
                    info!(
                        "scheduled next committee: {} (effective in {:?})",
                        committee.id,
                        deadline.saturating_duration_since(Instant::now())
                    );
                    self.state.next = Some((deadline, committee));
                },
                _ = async {
                    match &self.state.next {
                        Some((deadline, _)) => sleep_until(*deadline).await,
                        None => futures::future::pending().await,
                    }
                } => {
                    self.update().await?;
                }
            }
        }
    }

    async fn update(&mut self) -> Result<()> {
        let next = self
            .state
            .next
            .take()
            .expect("update called without next committee scheduled")
            .1;

        info!("switching to committee {}", next.id);

        self.state.node_urls = urls_from_config(&next)?;
        self.state.provider = build_provider(
            &self.state.node_urls[0].json_rpc_url,
            self.config.apikey.as_deref(),
        )
        .await?;
        self.state.current = next;
        self.state.next = None;

        Ok(())
    }

    async fn submit(&self, count: usize) -> Result<()> {
        let signers = &self.config.signers;
        let sender = signers[count % signers.len()].clone();
        let receiver = signers[(count + 1) % signers.len()].clone();

        let tx = if self.config.nitro {
            prepare(
                &self.state.provider,
                self.config.chain_id,
                sender,
                receiver.address(),
            )
            .await?
        } else {
            prepare_test(self.config.chain_id, sender, receiver.address())
        };

        match &self.strategy {
            SubmissionStrategy::Bundle(auction) => {
                let bundle = create_bundle(
                    self.config.enc_key.as_ref(),
                    self.state.current.id,
                    auction,
                    tx,
                    self.config.enc_ratio,
                    self.config.prio_ratio,
                )?;
                self.broadcast_bundle(&bundle).await;
            }
            SubmissionStrategy::RawTx => {
                let tx = create_tx(
                    self.config.enc_key.as_ref(),
                    self.state.current.id,
                    tx,
                    self.config.enc_ratio,
                )?;
                self.broadcast_tx(&tx).await;
            }
        }

        Ok(())
    }

    async fn broadcast_bundle(&self, bundle: &BundleVariant) {
        join_all(
            self.state
                .node_urls
                .iter()
                .map(|u| self.send_bundle(bundle, &u.regular_url, &u.priority_url)),
        )
        .await;
    }

    async fn broadcast_tx(&self, tx: &TransactionVariant) {
        join_all(
            self.state
                .node_urls
                .iter()
                .map(|u| self.send_tx(tx.clone(), &u.json_rpc_url)),
        )
        .await;
    }

    async fn send_tx(&self, tx: TransactionVariant, url: &Url) {
        let (method, params) = match tx {
            TransactionVariant::PlainText(t) => {
                ("eth_sendRawTransaction", vec![t.encode_hex_with_prefix()])
            }
            TransactionVariant::Encrypted(t) => {
                let chain_id: u64 = self.config.chain_id.into();
                (
                    "eth_sendEncTransaction",
                    vec![t.encode_hex_with_prefix(), chain_id.to_string()],
                )
            }
        };

        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: 1,
        };

        let result = self.client.post(url.clone()).json(&request).send().await;

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

async fn build_provider(url: &Url, apikey: Option<&str>) -> Result<RootProvider> {
    if let Some(apikey) = apikey {
        let key = HeaderValue::from_str(apikey)?;
        let hds = HeaderMap::from_iter([(AUTHORIZATION, key)]);
        let clt = Client::builder().default_headers(hds).build()?;
        let rpc = RpcClient::new_http_with_client(clt, url.clone());
        Ok(RootProvider::<Ethereum>::new(rpc))
    } else {
        Ok(RootProvider::<Ethereum>::connect(url.as_str()).await?)
    }
}

fn build_client(apikey: Option<&str>) -> Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(1));

    if let Some(key) = apikey {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", key))?,
        );
        builder = builder.default_headers(headers);
    }

    Ok(builder.build()?)
}

fn urls_from_config(committee: &CommitteeConfig) -> Result<Vec<ApiUrl>> {
    committee
        .members
        .iter()
        .cloned()
        .map(|m| {
            let addr = m.address.with_offset(HTTP_API_PORT_OFFSET);
            let regular_url = format!("http://{addr}/v1/submit/regular").parse()?;
            let priority_url = format!("http://{addr}/v1/submit/priority").parse()?;
            let json_rpc_url = format!("http://{addr}/v1/").parse()?;
            Ok(ApiUrl {
                regular_url,
                priority_url,
                json_rpc_url,
            })
        })
        .collect()
}

fn unix_to_instant(unix_secs: u64) -> Instant {
    let target = UNIX_EPOCH + Duration::from_secs(unix_secs);
    let now = SystemTime::now();

    match target.duration_since(now) {
        Ok(delta) => Instant::now() + delta,
        Err(_) => Instant::now(),
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

    let Ok(active) = contract.active().await else {
        bail!("no active committee on contract")
    };
    let committees = contract.subscribe(active.id).await?;

    let signers = args
        .signers
        .into_iter()
        .map(|k| PrivateKeySigner::from_str(&k))
        .collect::<Result<Vec<_>, _>>()?;

    let enc_key = if args.enc_ratio == 0f64 {
        None
    } else {
        let provider = ProviderBuilder::new().connect_http(chain_config.rpc_url.clone());
        let contract = KeyManager::new(chain_config.key_management_contract, provider);
        Some(ThresholdEncKey::from_bytes(
            &contract.thresholdEncryptionKey().call().await?.0,
        )?)
    };

    let auction = chain_config.auction_contract.map(Auction::new);

    let config = TxGeneratorConfig::builder()
        .tps(args.tps)
        .enc_ratio(args.enc_ratio)
        .prio_ratio(args.prio_ratio)
        .chain_id(args.namespace.into())
        .maybe_enc_key(enc_key)
        .signers(signers)
        .nitro(args.nitro)
        .maybe_apikey(args.apikey)
        .build();

    let tx_generator = TxGenerator::new(config, active, auction).await?;

    let mut jh = tokio::spawn(async move { tx_generator.generate(committees).await });

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
