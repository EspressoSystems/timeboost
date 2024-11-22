use anyhow::{bail, Result};
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use sailfish::{coordinator::Coordinator, sailfish::sailfish_coordinator};
use std::{collections::HashSet, sync::Arc};
use tide_disco::Url;
use tokio::sync::mpsc::channel;
use tracing::{error, info, instrument, warn};
use vbs::version::StaticVersion;

use hotshot_types::PeerConfig;
use multiaddr::{Multiaddr, PeerId};
use timeboost_core::{
    traits::comm::Libp2p,
    types::{
        event::TimeboostStatusEvent,
        metrics::{prometheus::PrometheusMetrics, ConsensusMetrics},
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
mod persistence;

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
        app_tx: Sender<TimeboostStatusEvent>,
        app_rx: Receiver<TimeboostStatusEvent>,
        shutdown_rx: watch::Receiver<()>,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            id,
            port,
            rpc_port,
            metrics_port,
            app_tx,
            app_rx,
            shutdown_rx,
            metrics,
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
            tokio::select! {
                result = coordinator.next() => match result {
                    Ok(actions) => {
                        for a in actions {
                            let event = coordinator.execute(a).await;
                            if let Ok(Some(e)) = event {
                                info!("Received event: {:?}", e)
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
    let metrics = Arc::new(ConsensusMetrics::new(prom.as_ref()));

    let (tb_app_tx, tb_app_rx) = channel(100);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
    let metrics_clone = metrics.clone();
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
        metrics,
    );

    info!("Timeboost is running.");
    timeboost.go(prom, coordinator).await
}
