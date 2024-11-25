use anyhow::{bail, Result};
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use futures::{future::BoxFuture, FutureExt};
use sailfish::{coordinator::Coordinator, sailfish::sailfish_coordinator};
use sequencer::{
    block_builder::NoOpBlockBuilder, decryption::NoOpDecryptionPhase,
    inclusion::NoOpInclusionPhase, ordering::NoOpOrderingPhase, protocol::Sequencer,
    task::run_sequencer_task,
};
use std::{
    collections::HashSet,
    future::pending,
    sync::Arc,
    time::{Duration, Instant},
};
use tide_disco::Url;
use timeboost_utils::types::PeerConfig;
use tokio::{sync::mpsc::channel, time::sleep};
use tracing::{debug, error, info, instrument, warn};
use vbs::version::StaticVersion;

use crate::mempool::Mempool;

use multiaddr::{Multiaddr, PeerId};
use timeboost_core::{
    traits::comm::Libp2p,
    types::{
        event::{SailfishEventType, TimeboostEventType, TimeboostStatusEvent},
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
pub mod contracts;
mod mempool;
mod producer;
pub mod sequencer;

/// The duration of an epoch in seconds.
const EPOCH_TIME_SECS: u64 = 60;

/// The time between consensus intervals in ms.
const CONSENSUS_INTERVAL_MS: u64 = 250;

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
    mempool: Mempool,

    /// The consensus protocol.
    consensus: Arc<
        Sequencer<NoOpInclusionPhase, NoOpDecryptionPhase, NoOpOrderingPhase, NoOpBlockBuilder>,
    >,

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
            mempool: Mempool::new(),
            epoch_clock: pending().boxed(),
            epoch_clock_start_time: Instant::now(),
            epoch: 0,
            consensus_interval_clock: pending().boxed(),
            consensus: Arc::new(Sequencer::new(
                NoOpInclusionPhase,
                NoOpDecryptionPhase,
                NoOpOrderingPhase,
                NoOpBlockBuilder,
                tb_metrics,
            )),
        }
    }

    #[instrument(level = "info", skip_all, fields(node = %self.id))]
    pub async fn go(
        mut self,
        prom: Arc<PrometheusMetrics>,
        coordinator: &mut Coordinator<Libp2p>,
    ) -> Result<()> {
        let app_tx = self.app_tx.clone();
        let rpc_handle = tokio::spawn(async move {
            let api = TimeboostApiState::new(app_tx);
            if let Err(e) = api
                .run(Url::parse(&format!("http://0.0.0.0:{}", self.rpc_port)).unwrap())
                .await
            {
                error!("failed to run timeboost api: {}", e);
            }
        });

        let metrics_handle = tokio::spawn(async move {
            serve_metrics_api::<StaticVersion<0, 1>>(self.metrics_port, prom).await
        });

        // Initialize the epoch clock. This clock is responsible for moving to the next epoch.
        self.epoch_clock = sleep(Duration::from_secs(EPOCH_TIME_SECS))
            .map(move |_| 0)
            .fuse()
            .boxed();

        // Initialize the consensus interval clock. This clock is responsible for triggering consensus.
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
                bail!("failed to start coordinator: {}", e);
            }
        }

        // Start the block producer.
        let (producer, p_tx) = producer::Producer::new(self.shutdown_rx.clone());
        tokio::spawn(producer.run());

        loop {
            tokio::select! { biased;
                round = &mut self.consensus_interval_clock => {
                    info!(%round, "starting timeboost consensus");
                    self.consensus_interval_clock = sleep(Duration::from_millis(CONSENSUS_INTERVAL_MS))
                        .map(move |_| round + 1)
                        .fuse()
                        .boxed();

                    let mempool_snapshot = self.mempool.drain_to_limit(mempool::MEMPOOL_LIMIT_BYTES);

                    // Make a new handle for the consensus protocol run.
                    let cx = self.consensus.clone();
                    let app_tx_clone = self.app_tx.clone();
                    let shutdown_rx = self.shutdown_rx.clone();
                    tokio::spawn(run_sequencer_task(
                        cx,
                        self.epoch,
                        round,
                        mempool_snapshot,
                        app_tx_clone,
                        shutdown_rx,
                    ));
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
                                        self.mempool.insert(block);
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
                        match event.event {
                            TimeboostEventType::Transactions { transactions } => {
                                coordinator.handle_transactions(transactions);
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
                result = self.shutdown_rx.changed() => {
                    warn!("received shutdown signal; shutting down.");

                    // Timeout waiting for all the handles to shut down
                    warn!("waiting for consensus handles to shut down");
                    let _ = tokio::time::sleep(Duration::from_secs(4)).await;

                    warn!("shutting down metrics handle");
                    metrics_handle.abort();

                    warn!("shutting down rpc handle");
                    rpc_handle.abort();

                    warn!("shutting down coordinator");
                    coordinator.shutdown().await.expect("shutdown coordinator");

                    result.expect("the shutdown sender was dropped before the receiver could receive the token");
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
