use std::net::SocketAddr;
use std::{sync::Arc, time::Duration};

use anyhow::{bail, Result};
use api::endpoints::TimeboostApiState;
use api::metrics::serve_metrics_api;
use cliquenet::{Address, Network, NetworkMetrics};
use keyset::DecryptionInfo;
use metrics::TimeboostMetrics;
use parking_lot::Mutex;
use reqwest::Url;
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcConfig, RbcMetrics};
use sailfish::types::{Action, DataSource};
use sailfish::Coordinator;
use sequencer::{
    phase::{
        block_builder::noop::NoOpBlockBuilder, decryption::noop::NoOpDecryptionPhase,
        inclusion::noop::NoOpInclusionPhase, ordering::noop::NoOpOrderingPhase,
    },
    protocol::Sequencer,
};
use timeboost_core::load_generation::{make_tx, tps_to_millis};
use timeboost_core::types::block::sailfish::SailfishBlock;
use timeboost_core::types::time::Timestamp;
use timeboost_core::types::transaction::Transaction;
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::time::interval;
use tokio::{sync::mpsc::channel, task::JoinHandle};
use tracing::{error, instrument, trace, warn};
use vbs::version::StaticVersion;

use crate::mempool::Mempool;

use multisig::{Committee, Keypair, PublicKey};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::event::{TimeboostEventType, TimeboostStatusEvent};
use tokio::sync::mpsc::{Receiver, Sender};

pub mod api;
pub mod gas;
pub mod keyset;
mod mempool;
pub mod metrics;
mod producer;
pub mod sequencer;

type SailfishCoordinator = Coordinator<SailfishBlock, Rbc<SailfishBlock>>;

pub struct TimeboostInitializer {
    /// The port to bind the RPC server to.
    pub rpc_port: u16,

    /// The port to bind the metrics API server to.
    pub metrics_port: u16,

    /// The peers that this node will connect to.
    pub peers: Vec<(PublicKey, Address)>,

    /// The keypair for the node.
    pub keypair: Keypair,

    /// The decryption key material for the node.
    pub deckey: DecryptionInfo,

    /// The bind address for the node.
    pub bind_address: SocketAddr,

    /// The url for arbitrum nitro node for gas calculations
    pub nitro_url: Option<reqwest::Url>,

    /// The sender for events to the sailfish node.
    pub app_tx: Sender<TimeboostStatusEvent>,

    /// The receiver for events to the sailfish node.
    pub app_rx: Receiver<TimeboostStatusEvent>,
}

pub struct Timeboost {
    /// The port to bind the metrics API server to.
    metrics_port: u16,

    /// The sender for events to the sailfish node.
    app_tx: Sender<TimeboostStatusEvent>,

    /// The receiver for events to the sailfish node.
    app_rx: Receiver<TimeboostStatusEvent>,

    /// The mempool for the timeboost node.
    mempool: Arc<Mempool>,

    /// The coordinator for the timeboost node.
    coordinator: SailfishCoordinator,

    /// The prometheus metrics for all the metrics layers.
    metrics: Arc<PrometheusMetrics>,

    /// The timeboost metrics layer.
    tb_metrics: Arc<TimeboostMetrics>,

    /// Sender for SailfishBlock to estimation task
    block_tx: Sender<SailfishBlock>,

    /// Task handles
    handles: Vec<JoinHandle<()>>,

    transactions: TransactionQueue,
}

#[derive(Clone)]
pub struct TransactionQueue(Arc<Mutex<Vec<Transaction>>>);

impl TransactionQueue {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
}

impl DataSource for TransactionQueue {
    type Data = SailfishBlock;

    fn next(&mut self, _: sailfish::types::RoundNumber) -> Self::Data {
        let transactions = std::mem::take(&mut *self.0.lock());
        SailfishBlock::new(Timestamp::now(), transactions, 0)
    }
}

/// Asynchronously initializes and constructs a `Timeboost` instance from the provided initializer.
///
/// This method:
/// - Sets up various metrics collectors using Prometheus.
/// - Creates communication channels for application messages.
/// - Constructs a `Committee` from peer information.
/// - Initializes a network layer with the given configuration.
/// - Configures and initializes an RBC (Reliable Broadcast) protocol.
/// - Builds a `Sailfish` instance using the `SailfishInitializer`.
/// - Converts the `Sailfish` into a coordinator for managing consensus.
/// - Sets up a mempool for transaction handling.
/// - Finally, it assembles all components into a `Timeboost` node.
///
/// # Panics
///
/// - This method uses `expect` and `unwrap`, which will panic if their conditions are not met. This includes:
///   - Network creation failure.
///   - Failure in building the `SailfishInitializer`.
///   - Any errors during `Sailfish::initialize`.
#[async_trait::async_trait]
impl HasInitializer for Timeboost {
    type Initializer = TimeboostInitializer;
    type Into = Self;

    async fn initialize(initializer: Self::Initializer) -> Result<Self> {
        let prom = Arc::new(PrometheusMetrics::default());
        let sf_metrics = ConsensusMetrics::new(prom.as_ref());
        let tb_metrics = Arc::new(TimeboostMetrics::new(prom.as_ref()));
        let rbc_metrics = RbcMetrics::new(prom.as_ref());
        let net_metrics =
            NetworkMetrics::new(prom.as_ref(), initializer.peers.iter().map(|(k, _)| *k));

        let (block_tx, block_rx) = channel(1000);

        let committee = Committee::new(
            initializer
                .peers
                .iter()
                .map(|b| b.0)
                .enumerate()
                .map(|(i, key)| (i as u8, key)),
        );

        let network = Network::create(
            initializer.bind_address,
            initializer.keypair.clone(),
            initializer.peers,
            net_metrics,
        )
        .await
        .expect("failed to connect to remote nodes");

        let cfg = RbcConfig::new(initializer.keypair.clone(), committee.clone());
        let rbc = Rbc::new(network, cfg.with_metrics(rbc_metrics));

        let producer = TransactionQueue::new();
        let consensus = Consensus::new(initializer.keypair, committee, producer.clone())
            .with_metrics(sf_metrics);
        let coordinator = Coordinator::new(rbc, consensus);

        let mempool = Arc::new(Mempool::new(initializer.nitro_url, block_rx));

        // Then, initialize and run the timeboost node.
        let timeboost = Timeboost {
            metrics_port: initializer.metrics_port,
            app_tx: initializer.app_tx,
            app_rx: initializer.app_rx,
            mempool,
            coordinator,
            metrics: prom,
            tb_metrics,
            block_tx,
            handles: vec![],
            transactions: producer,
        };

        Ok(timeboost)
    }
}

impl Drop for Timeboost {
    fn drop(&mut self) {
        warn!("shutting down timeboost.");
        for h in self.handles.iter() {
            h.abort();
        }
    }
}

impl Timeboost {
    /// Spawns a task that will continuously send transactions to the timeboost app layer
    fn start_load_generator(tps: u32, app_tx: Sender<TimeboostStatusEvent>) -> JoinHandle<()> {
        let millis = tps_to_millis(tps);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(millis));
            #[allow(clippy::redundant_pattern_matching)]
            while let Some(_) = interval.tick().await.into() {
                let tx = make_tx();
                match app_tx
                    .send(TimeboostStatusEvent {
                        event: TimeboostEventType::Transactions {
                            transactions: vec![tx],
                        },
                    })
                    .await
                {
                    Ok(_) => {
                        trace!("tranaction sent successfully");
                    }
                    Err(e) => {
                        error!(%e, "failed to send transaction");
                    }
                }
            }
        })
    }

    /// Run the timeboost app
    ///
    /// This function will:
    /// - Start the metrics and rpc api to query data and get post transactions
    /// - Start load generation if there is transactions per second defined
    /// - Start the sequencer with its phases and run it in its own task
    /// - Start block producer and run it in its own task
    /// - Start and run the `Sailfish Coordinator` to retrieve network messages by calling `next` and executing actions after message is processed
    /// - Runs a channel to receive `TimeboostEventType` this will receive transactions and send completed blocks to the producer
    /// - Will continuously run until there is a shutdown signal received
    #[instrument(level = "info", skip_all, fields(node = %self.coordinator.public_key()))]
    pub async fn go(mut self, committee_size: usize, tps: u32) -> Result<()> {
        let app_tx = self.app_tx.clone();
        self.handles
            .push(start_metrics_api(self.metrics.clone(), self.metrics_port));

        // Start the load generator.
        if tps > 0 {
            self.handles.push(Self::start_load_generator(tps, app_tx));
        } else {
            warn!("running without load generator");
        }

        let sequencer = Sequencer::new(
            NoOpInclusionPhase,
            NoOpDecryptionPhase,
            NoOpOrderingPhase,
            NoOpBlockBuilder,
            self.tb_metrics.clone(),
            self.mempool.clone(),
        );

        // Start the sequencer.
        self.handles.push(tokio::spawn(
            sequencer.go(self.app_tx.clone(), committee_size),
        ));

        // Start the block producer.
        let (producer, p_tx) = producer::Producer::new();

        self.handles.push(tokio::spawn(producer.run()));

        // Kickstart the network.
        for a in self.coordinator.init() {
            let _ = self.coordinator.execute(a).await;
        }
        loop {
            tokio::select! { biased;
                result = self.coordinator.next() => match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                let (.., b) = payload.into_parts();
                                if !b.is_empty() {
                                    if self.mempool.run_estimator() {
                                        // Send to the estimation task
                                        // There we will estimate transactions and insert block into mempool
                                        let _ = self.block_tx.send(b).await;
                                    } else {
                                        self.mempool.insert(b);
                                    }
                                }
                            } else if let Err(e) = self.coordinator.execute(a).await {
                                tracing::error!("coordinator execution error: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error receiving message: {}", e);
                    },
                },
                tb_event = self.app_rx.recv() => match tb_event {
                    Some(event) => {
                        match event.event {
                            TimeboostEventType::Transactions { transactions } => {
                                self.transactions.0.lock().extend_from_slice(&transactions);
                            }
                            TimeboostEventType::BlockBuilt { block } => {
                                let _ = p_tx.send(block).await;
                            }
                        }

                    }
                    None => {
                        // If we get here, it's a big deal.
                        bail!("Receiver disconnected while awaiting application layer messages.");
                    }
                },
            }
        }
    }
}

pub fn start_rpc_api(app_tx: Sender<TimeboostStatusEvent>, rpc_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let api = TimeboostApiState::new(app_tx);
        tracing::info!("starting rpc api on port {}", rpc_port);
        if let Err(e) = api
            .run(Url::parse(&format!("http://0.0.0.0:{}", rpc_port)).unwrap())
            .await
        {
            error!("failed to run timeboost api: {}", e);
        }
    })
}

/// Start out metrics api with given port
pub fn start_metrics_api(metrics: Arc<PrometheusMetrics>, metrics_port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("starting metrics api on port {}", metrics_port);
        serve_metrics_api::<StaticVersion<0, 1>>(metrics_port, metrics).await
    })
}
