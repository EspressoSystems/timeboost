use anyhow::Result;
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use std::{collections::HashSet, sync::Arc};
use tide_disco::Url;
use tokio::sync::mpsc::channel;
use tracing::{error, info, instrument, warn};
use vbs::version::StaticVersion;

use hotshot_types::PeerConfig;
use multiaddr::{Multiaddr, PeerId};
use sailfish::sailfish::{run_sailfish, ShutdownToken};
use timeboost_core::types::{
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    metrics::{prometheus::PrometheusMetrics, ConsensusMetrics},
    Keypair, NodeId, PublicKey,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    watch,
};

pub mod api;
pub mod config;
pub mod contracts;

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

    /// The receiver for events from the sailfish node.
    app_rx: Receiver<SailfishStatusEvent>,

    /// The sender for events to the sailfish node.
    app_tx: Sender<TimeboostStatusEvent>,

    /// The receiver for the shutdown signal.
    shutdown_rx: watch::Receiver<ShutdownToken>,

    /// The metrics for the timeboost node.
    #[allow(dead_code)]
    metrics: Arc<ConsensusMetrics>,
}

impl Timeboost {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: NodeId,
        port: u16,
        rpc_port: u16,
        metrics_port: u16,
        app_rx: Receiver<SailfishStatusEvent>,
        app_tx: Sender<TimeboostStatusEvent>,
        shutdown_rx: watch::Receiver<ShutdownToken>,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            id,
            port,
            rpc_port,
            metrics_port,
            app_rx,
            app_tx,
            shutdown_rx,
            metrics,
        }
    }

    #[instrument(level = "info", skip_all, fields(node = %self.id))]
    pub async fn go(mut self, prom: Arc<PrometheusMetrics>) -> Result<ShutdownToken> {
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

        loop {
            tokio::select! {
                event = self.app_rx.recv() => {
                    match event {
                        Some(event) => info!("Received event: {:?}", event),
                        None => {
                            warn!("Timeboost channel closed; shutting down.");
                            break Err(anyhow::anyhow!("Timeboost channel closed; shutting down."));
                        }
                    }
                }
                result = self.shutdown_rx.changed() => {
                    warn!("Received shutdown signal; shutting down.");
                    result.expect("The shutdown sender was dropped before the receiver could receive the token");
                    return Ok(self.shutdown_rx.borrow().clone());
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
    shutdown_rx: watch::Receiver<ShutdownToken>,
) -> Result<ShutdownToken> {
    info!("Starting timeboost");

    let prom = Arc::new(PrometheusMetrics::default());
    let metrics = Arc::new(ConsensusMetrics::new(prom.as_ref()));

    // The application layer will broadcast events to the timeboost node.
    let (sf_app_tx, sf_app_rx) = channel(100);

    let (tb_app_tx, tb_app_rx) = channel(100);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
    let metrics_clone = metrics.clone();
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(async move {
        run_sailfish(
            id,
            bootstrap_nodes,
            staked_nodes,
            keypair,
            bind_address,
            sf_app_tx,
            tb_app_rx,
            metrics_clone,
            shutdown_rx_clone,
        )
        .await
    });

    // Then, initialize and run the timeboost node.
    let timeboost = Timeboost::new(
        id,
        port,
        rpc_port,
        metrics_port,
        sf_app_rx,
        tb_app_tx,
        shutdown_rx,
        metrics,
    );

    info!("Timeboost is running.");
    timeboost.go(prom).await
}
