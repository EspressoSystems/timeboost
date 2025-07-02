mod config;

use std::iter::once;
use std::sync::Arc;

use anyhow::Result;
use api::metrics::serve_metrics_api;
use metrics::TimeboostMetrics;
use multisig::PublicKey;
use reqwest::Url;
use timeboost_builder::{BlockProducer, ProducerDown};
use timeboost_sequencer::Sequencer;
use timeboost_types::BundleVariant;
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::task::spawn;
use tracing::{error, info, instrument, warn};
use vbs::version::StaticVersion;

pub use config::{TimeboostConfig, TimeboostConfigBuilder};
pub use timeboost_builder as builder;
pub use timeboost_crypto as crypto;
pub use timeboost_proto as proto;
pub use timeboost_sequencer as sequencer;
pub use timeboost_types as types;

use crate::forwarder::data::Data;
use crate::forwarder::nitro_forwarder::NitroForwarder;

pub mod api;
pub mod forwarder;
pub mod gas;
pub mod mempool;
pub mod metrics;

pub struct Timeboost {
    label: PublicKey,
    config: TimeboostConfig,
    receiver: Receiver<BundleVariant>,
    sequencer: Sequencer,
    producer: BlockProducer,
    prometheus: Arc<PrometheusMetrics>,
    _metrics: Arc<TimeboostMetrics>,
    nitro_forwarder: Option<NitroForwarder>,
    children: Vec<JoinHandle<()>>,
}

impl Timeboost {
    pub async fn new(cfg: TimeboostConfig, rx: Receiver<BundleVariant>) -> Result<Self> {
        let pro = Arc::new(PrometheusMetrics::default());
        let met = Arc::new(TimeboostMetrics::new(&*pro));
        let seq = Sequencer::new(cfg.sequencer_config(), &*pro).await?;
        let blk = BlockProducer::new(cfg.producer_config(), &*pro).await?;

        // TODO: Once we have e2e listener this check wont be needed
        let nitro_forwarder = if let Some(nitro_addr) = cfg.nitro_addr.clone() {
            Some(NitroForwarder::connect(cfg.sign_keypair.public_key(), nitro_addr).await?)
        } else {
            None
        };

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            config: cfg,
            receiver: rx,
            sequencer: seq,
            producer: blk,
            prometheus: pro,
            _metrics: met,
            nitro_forwarder,
            children: Vec::new(),
        })
    }

    /// Run the timeboost app
    #[instrument(level = "info", skip_all)]
    pub async fn go(mut self) -> Result<()> {
        self.children.push(spawn(metrics_api(
            self.prometheus.clone(),
            self.config.metrics_port,
        )));

        loop {
            select! {
                trx = self.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundles(once(t))
                    }
                },
                trx = self.sequencer.next_transactions() => match trx {
                    Ok(o) => {
                        info!(
                            node  = %self.label,
                            round = %o.round(),
                            trxs  = %o.txns().len(),
                            "sequencer output"
                        );
                        if let Some(ref mut f) = self.nitro_forwarder {
                            if let Ok(d) = Data::encode(o.round(), o.time(), o.txns()) {
                                f.enqueue(d).await?;
                            } else {
                                error!(node = %self.label, "failed to encode inclusion list")
                            }
                        } else {
                            warn!(
                                node  = %self.label,
                                round = %o.round(),
                                "no forwarder configured => dropping sequencer output"
                            )
                        }
                    }
                    Err(err) => {
                        return Err(err.into())
                    }
                },
                blk = self.producer.next_block() => match blk {
                    Ok(b) => {
                        info!(node = %self.label, block = %b.data().round(), "certified block");
                    }
                    Err(e) => {
                        let e: ProducerDown = e;
                        return Err(e.into())
                    }
                }
            }
        }
    }
}

pub async fn metrics_api(metrics: Arc<PrometheusMetrics>, metrics_port: u16) {
    serve_metrics_api::<StaticVersion<0, 1>>(metrics_port, metrics).await
}

pub async fn rpc_api(sender: Sender<BundleVariant>, rpc_port: u16) {
    if let Err(e) = api::endpoints::TimeboostApiState::new(sender)
        .run(Url::parse(&format!("http://0.0.0.0:{rpc_port}")).unwrap())
        .await
    {
        error!("failed to run timeboost api: {}", e);
    }
}
