use anyhow::{bail, Result};
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use consensus::{
    block_builder::NoOpBlockBuilder, decryption::NoOpDecryptionPhase,
    inclusion::NoOpInclusionPhase, ordering::NoOpOrderingPhase, protocol::Consensus,
};
use futures::{future::BoxFuture, FutureExt};
use sailfish::{coordinator::Coordinator, sailfish::sailfish_coordinator};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::pending,
    sync::Arc,
    time::{Duration, Instant},
};
use tide_disco::Url;
use tokio::{
    sync::{mpsc::channel, RwLock},
    task::JoinHandle,
    time::sleep,
};
use tracing::{debug, error, info, instrument, warn};
use vbs::version::StaticVersion;

use hotshot_types::PeerConfig;
use multiaddr::{Multiaddr, PeerId};
use timeboost_core::{
    traits::comm::Libp2p,
    types::{
        block::Block,
        event::{SailfishEventType, TimeboostStatusEvent},
        metrics::{prometheus::PrometheusMetrics, SailfishMetrics, TimeboostMetrics},
        Keypair, NodeId, PublicKey,
    },
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    watch,
};

pub mod api;
pub mod config;
pub mod consensus;
pub mod contracts;
mod persistence;

/// The duration of an epoch in seconds.
const EPOCH_TIME_SECS: u64 = 60;

/// The time between consensus intervals in ms.
const CONSENSUS_INTERVAL_MS: u64 = 250;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of blocks in the mempool.
    blocks: VecDeque<Block>,
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        Self {
            blocks: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, block: Block) {
        self.blocks.push_back(block);
    }

    /// Drains blocks from the mempool until the total size reaches `limit_bytes`.
    pub fn drain_to_limit(&mut self, limit_bytes: usize) -> Vec<Block> {
        let mut total_size = 0;
        self.blocks
            .drain(..)
            .take_while(|block| {
                let should_take = total_size + block.size_bytes() <= limit_bytes;
                if should_take {
                    total_size += block.size_bytes();
                }
                should_take
            })
            .collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Timeboost {
    /// The ID of the node.
    id: NodeId,

    /// The port to bind timeboost to.
    #[allow(dead_code)]
    port: u16,

    /// The port to bind the RPC server to.
    rpc_port: u16,

    /// The port to bind the metrics API server to.
    metrics_port: u16,

    /// The sender for events to the sailfish node.
    app_tx: Sender<TimeboostStatusEvent>,

    /// The receiver for events to the sailfish node.
    app_rx: Receiver<TimeboostStatusEvent>,

    /// The receiver for the shutdown signal.
    shutdown_rx: watch::Receiver<()>,

    /// The timeboost clock
    epoch_clock: BoxFuture<'static, u64>,

    /// The time the clock started.
    epoch_clock_start_time: Instant,

    /// The consensus interval clock.
    consensus_interval_clock: BoxFuture<'static, u64>,

    /// The current epoch.
    epoch: u64,

    /// The mempool for the timeboost node.
    mempool: Arc<RwLock<Mempool>>,

    /// The consensus protocol.
    consensus: Arc<
        Consensus<NoOpInclusionPhase, NoOpDecryptionPhase, NoOpOrderingPhase, NoOpBlockBuilder>,
    >,

    /// The consensus protocl handles
    cx_handles: HashMap<u64, JoinHandle<()>>,

    /// The metrics for the sailfish node.
    #[allow(dead_code)]
    sf_metrics: Arc<SailfishMetrics>,

    /// The metrics for the timeboost node.
    #[allow(dead_code)]
    tb_metrics: Arc<TimeboostMetrics>,
}

impl Timeboost {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: NodeId,
        port: u16,
        rpc_port: u16,
        metrics_port: u16,
        app_tx: Sender<TimeboostStatusEvent>,
        app_rx: Receiver<TimeboostStatusEvent>,
        shutdown_rx: watch::Receiver<()>,
        sf_metrics: Arc<SailfishMetrics>,
        tb_metrics: Arc<TimeboostMetrics>,
    ) -> Self {
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        Self {
            id,
            port,
            rpc_port,
            metrics_port,
            app_tx,
            app_rx,
            shutdown_rx,
            sf_metrics,
            tb_metrics: tb_metrics.clone(),
            mempool: mempool.clone(),
            epoch_clock: pending().boxed(),
            epoch_clock_start_time: Instant::now(),
            epoch: 0,
            consensus_interval_clock: pending().boxed(),
            consensus: Arc::new(Consensus::new(
                Arc::new(NoOpInclusionPhase),
                Arc::new(NoOpDecryptionPhase),
                Arc::new(NoOpOrderingPhase),
                Arc::new(NoOpBlockBuilder),
                tb_metrics,
            )),
            cx_handles: HashMap::new(),
        }
    }

    #[instrument(level = "info", skip_all, fields(node = %self.id))]
    pub async fn go(
        mut self,
        prom: Arc<PrometheusMetrics>,
        coordinator: &mut Coordinator<Libp2p>,
    ) -> Result<()> {
        tokio::spawn(async move {
            let api = TimeboostApiState::new(self.app_tx.clone());
            if let Err(e) = api
                .run(Url::parse(&format!("http://0.0.0.0:{}", self.rpc_port)).unwrap())
                .await
            {
                error!("Failed to run timeboost api: {}", e);
            }
        });

        tokio::spawn(async move {
            serve_metrics_api::<StaticVersion<0, 1>>(self.metrics_port, prom).await
        });

        // Initialize the clock.
        self.epoch_clock = sleep(Duration::from_secs(EPOCH_TIME_SECS))
            .map(move |_| 0)
            .fuse()
            .boxed();

        // The consensus interval clock.
        self.consensus_interval_clock = sleep(Duration::from_millis(CONSENSUS_INTERVAL_MS))
            .map(move |_| 0)
            .fuse()
            .boxed();

        // Kickstart the network.
        match coordinator.start().await {
            Ok(actions) => {
                for a in actions {
                    let _ = coordinator.execute(a).await;
                }
            }
            Err(e) => {
                bail!("Failed to start coordinator: {}", e);
            }
        }

        loop {
            tokio::select! { biased;
                round = &mut self.consensus_interval_clock => {
                    self.consensus_interval_clock = sleep(Duration::from_millis(CONSENSUS_INTERVAL_MS))
                        .map(move |_| round + 1)
                        .fuse()
                        .boxed();
                    let mempool_snapshot = {
                        let mut mempool = self.mempool.write().await;
                        mempool.drain_to_limit(1024 * 1024)
                    };

                    // Make a new handle for the consensus protocol run.
                    let cx = self.consensus.clone();
                    let cx_handle = tokio::spawn(async move {
                        let _ = cx.start(self.epoch, mempool_snapshot).await;
                    });

                    // Sanity check.
                    debug_assert!(!self.cx_handles.contains_key(&round));

                    self.cx_handles.insert(round, cx_handle);
                }
                _ = &mut self.epoch_clock => {
                    self.epoch_clock = sleep(Duration::from_secs(EPOCH_TIME_SECS))
                        .map(move |_| {
                            let elapsed = Instant::now().duration_since(self.epoch_clock_start_time);
                            let epoch = elapsed.as_secs() / EPOCH_TIME_SECS;
                            self.epoch = epoch;
                            epoch
                        })
                        .fuse()
                        .boxed();
                }
                result = coordinator.next() => match result {
                    Ok(actions) => {
                        for a in actions {
                            let event = coordinator.execute(a).await;
                            if let Ok(Some(e)) = event {
                                match e.event {
                                    SailfishEventType::Error { error } => {
                                        error!(%error, "sailfish encountered an error");
                                    },
                                    SailfishEventType::RoundFinished { round: _ } => {
                                        debug!("round finished");
                                    },
                                    SailfishEventType::Timeout { round: _ } => {
                                        debug!("timeout");
                                    },
                                    SailfishEventType::Committed { round: _, block } => {
                                        self.mempool.write().await.insert(block);
                                    },
                                }
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error receiving message: {}", e);
                    },
                },
                tb_event = self.app_rx.recv() => match tb_event {
                    Some(event) => {
                        coordinator.handle_tb_event(event).await?;
                    }
                    None => {
                        // If we get here, it's a big deal.
                        bail!("Receiver disconnected while awaiting application layer messages.");
                    }
                },
                result = self.shutdown_rx.changed() => {
                    warn!("Received shutdown signal; shutting down.");
                    coordinator.shutdown().await.expect("Shutdown coordinator");

                    // Timeout waiting for all the handles to shut down
                    let _ = tokio::time::timeout(Duration::from_secs(4), async move {
                        while let Some(handle) = self.cx_handles.values().next() {
                            handle.abort();
                        }
                    }).await;

                    result.expect("The shutdown sender was dropped before the receiver could receive the token");
                    return Ok(());
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_timeboost(
    id: NodeId,
    port: u16,
    rpc_port: u16,
    metrics_port: u16,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
    shutdown_rx: watch::Receiver<()>,
) -> Result<()> {
    info!("Starting timeboost");

    let prom = Arc::new(PrometheusMetrics::default());
    let sf_metrics = Arc::new(SailfishMetrics::new(prom.as_ref()));
    let tb_metrics = Arc::new(TimeboostMetrics::new(prom.as_ref()));
    let (tb_app_tx, tb_app_rx) = channel(100);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
    let metrics_clone = sf_metrics.clone();
    let coordinator = &mut sailfish_coordinator(
        id,
        bootstrap_nodes,
        staked_nodes,
        keypair,
        bind_address,
        metrics_clone,
    )
    .await;

    // Then, initialize and run the timeboost node.
    let timeboost = Timeboost::new(
        id,
        port,
        rpc_port,
        metrics_port,
        tb_app_tx,
        tb_app_rx,
        shutdown_rx,
        sf_metrics,
        tb_metrics,
    );

    info!("Timeboost is running.");
    timeboost.go(prom, coordinator).await
}
