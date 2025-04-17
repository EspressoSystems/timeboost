use std::iter::once;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{sync::Arc, time::Duration};

use anyhow::Result;
use api::metrics::serve_metrics_api;
use cliquenet::Address;
use metrics::TimeboostMetrics;
use reqwest::Url;
use timeboost_crypto::DecryptionScheme;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_sequencer::{Sequencer, SequencerConfig};
use timeboost_types::{BundleVariant, DecryptionKey};
use timeboost_utils::load_generation::{make_bundle, tps_to_millis};
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::task::spawn;
use tokio::time::interval;
use tracing::{error, info, instrument, warn};
use vbs::version::StaticVersion;

use multisig::{Keypair, PublicKey};
use tokio::sync::mpsc::{Receiver, Sender};

pub use timeboost_types as types;

pub mod api;
pub mod keyset;
pub mod metrics;

type EncKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;

pub struct TimeboostConfig {
    /// The port to bind the RPC server to.
    pub rpc_port: u16,

    /// The port to bind the metrics API server to.
    pub metrics_port: u16,

    /// The peers that this node will connect to.
    pub peers: Vec<(PublicKey, Address)>,

    /// The keypair for the node.
    pub keypair: Keypair,

    /// The decryption key material for the node.
    pub dec_sk: DecryptionKey,

    /// The bind address for the node.
    pub bind_address: SocketAddr,

    /// The url for arbitrum nitro node for gas calculations
    pub nitro_url: Option<reqwest::Url>,

    /// The sender for transactions.
    pub sender: Sender<BundleVariant>,

    /// The receiver for transactions.
    pub receiver: Receiver<BundleVariant>,

    /// Transactions per second
    pub tps: u32,

    /// Path to a file that this process creates or reads as execution proof.
    pub stamp: PathBuf,

    /// Ignore any existing stamp file and start with genesis round.
    pub ignore_stamp: bool,
}

pub struct Timeboost {
    label: PublicKey,
    init: TimeboostConfig,
    sequencer: Sequencer,
    prometheus: Arc<PrometheusMetrics>,
    _metrics: Arc<TimeboostMetrics>,
    children: Vec<JoinHandle<()>>,
}

impl Timeboost {
    pub async fn new(init: TimeboostConfig) -> Result<Self> {
        let recover = if init.ignore_stamp {
            false
        } else {
            tokio::fs::try_exists(&init.stamp).await?
        };

        let scf =
            SequencerConfig::new(init.keypair.clone(), init.dec_sk.clone(), init.bind_address)
                .recover(recover)
                .with_peers(init.peers.clone());
        let pro = Arc::new(PrometheusMetrics::default());
        let seq = Sequencer::new(scf, &*pro).await?;
        let met = Arc::new(TimeboostMetrics::new(&*pro));
        Ok(Self {
            label: init.keypair.public_key(),
            init,
            sequencer: seq,
            prometheus: pro,
            _metrics: met,
            children: Vec::new(),
        })
    }

    /// Run the timeboost app
    #[instrument(level = "info", skip_all)]
    pub async fn go(mut self) -> Result<()> {
        self.children.push(spawn(metrics_api(
            self.prometheus.clone(),
            self.init.metrics_port,
        )));

        if self.init.tps > 0 {
            self.children.push(spawn(gen_bundles(
                self.init.tps,
                self.init.dec_sk.pubkey().clone(),
                self.init.sender.clone(),
            )));
        }

        tokio::fs::File::create(self.init.stamp)
            .await?
            .sync_all()
            .await?;

        loop {
            select! { biased;
                trx = self.sequencer.next_transaction() => match trx {
                    Ok(trx) => {
                        info!(node = %self.label, trx = %trx.tx().hash(), "transaction");
                        // TODO: block building phase
                    }
                    Err(err) => {
                        return Err(err.into())
                    }
                },
                trx = self.init.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundles(once(t))
                    }
                }
            }
        }
    }
}

async fn gen_bundles(tps: u32, pubkey: EncKey, tx: Sender<BundleVariant>) {
    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    loop {
        interval.tick().await;
        let Ok(b) = make_bundle(&pubkey) else {
            warn!("error generating bundle");
            continue;
        };
        if tx.send(b).await.is_err() {
            error!("unable to send bundle");
            return;
        }
    }
}

pub async fn metrics_api(metrics: Arc<PrometheusMetrics>, metrics_port: u16) {
    serve_metrics_api::<StaticVersion<0, 1>>(metrics_port, metrics).await
}

pub async fn rpc_api(sender: Sender<BundleVariant>, rpc_port: u16) {
    if let Err(e) = api::endpoints::TimeboostApiState::new(sender)
        .run(Url::parse(&format!("http://0.0.0.0:{}", rpc_port)).unwrap())
        .await
    {
        error!("failed to run timeboost api: {}", e);
    }
}
