use std::iter::once;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use api::metrics::serve_metrics_api;
use cliquenet::Address;
use metrics::TimeboostMetrics;
use multisig::{Keypair, PublicKey, x25519};
use reqwest::Url;
use timeboost_builder::{BlockProducer, BlockProducerConfig, ProducerDown};
use timeboost_sequencer::{Sequencer, SequencerConfig};
use timeboost_types::{BundleVariant, DecryptionKey};
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::task::spawn;
use tracing::{error, info, instrument};
use vbs::version::StaticVersion;

pub use timeboost_types as types;

pub mod api;
pub mod metrics;

pub struct TimeboostConfig {
    /// The port to bind the RPC server to.
    pub rpc_port: u16,

    /// The port to bind the metrics API server to.
    pub metrics_port: u16,

    /// The sailfish peers that this node will connect to.
    pub sailfish_peers: Vec<(PublicKey, x25519::PublicKey, Address)>,

    /// The decrypt peers that this node will connect to.
    pub decrypt_peers: Vec<(PublicKey, x25519::PublicKey, Address)>,

    /// The block producer peers that this node will connect to.
    pub producer_peers: Vec<(PublicKey, x25519::PublicKey, Address)>,

    /// The keypair for the node to sign messages.
    pub sign_keypair: Keypair,

    /// The keypair for Diffie-Hellman key exchange.
    pub dh_keypair: x25519::Keypair,

    /// The decryption key material for the node.
    pub dec_sk: DecryptionKey,

    /// The bind address for the sailfish node.
    pub sailfish_address: Address,

    /// The bind address for the decrypter node.
    pub decrypt_address: Address,

    /// The bind address for the block producer node.
    pub producer_address: Address,

    /// The url for arbitrum nitro node for gas calculations
    pub nitro_url: Option<reqwest::Url>,

    /// The sender for transactions.
    pub sender: Sender<BundleVariant>,

    /// The receiver for transactions.
    pub receiver: Receiver<BundleVariant>,

    /// Path to a file that this process creates or reads as execution proof.
    pub stamp: PathBuf,

    /// Ignore any existing stamp file and start with genesis round.
    pub ignore_stamp: bool,
}

pub struct Timeboost {
    label: PublicKey,
    init: TimeboostConfig,
    sequencer: Sequencer,
    producer: BlockProducer,
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

        let scf = SequencerConfig::new(
            init.sign_keypair.clone(),
            init.dh_keypair.clone(),
            init.dec_sk.clone(),
            init.sailfish_address.clone(),
            init.decrypt_address.clone(),
        )
        .recover(recover)
        .with_sailfish_peers(init.sailfish_peers.clone())
        .with_decrypt_peers(init.decrypt_peers.clone());

        let bcf = BlockProducerConfig::new(
            init.sign_keypair.clone(),
            init.dh_keypair.clone(),
            init.producer_address.clone(),
        )
        .with_peers(init.producer_peers.clone());

        let pro = Arc::new(PrometheusMetrics::default());
        let seq = Sequencer::new(scf, &*pro).await?;
        let blk = BlockProducer::new(bcf, &*pro).await?;
        let met = Arc::new(TimeboostMetrics::new(&*pro));

        Ok(Self {
            label: init.sign_keypair.public_key(),
            init,
            sequencer: seq,
            producer: blk,
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

        tokio::fs::File::create(self.init.stamp)
            .await?
            .sync_all()
            .await?;

        loop {
            select! {
                trx = self.init.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundles(once(t))
                    }
                },
                trx = self.sequencer.next_transactions() => match trx {
                    Ok(trx) => {
                        info!(node = %self.label, len = %trx.len(), "next batch of transactions");
                        let res: Result<(), ProducerDown> = self.producer.enqueue(trx).await;
                        res?
                    }
                    Err(err) => {
                        return Err(err.into())
                    }
                },
                blk = self.producer.next_block() => match blk {
                    Ok(b) => {
                        info!(node = %self.label, block = %b.num(), "certified block");
                        let res: Result<(), ProducerDown> = self.producer.gc(b.num()).await;
                        res?
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
        .run(Url::parse(&format!("http://0.0.0.0:{}", rpc_port)).unwrap())
        .await
    {
        error!("failed to run timeboost api: {}", e);
    }
}
