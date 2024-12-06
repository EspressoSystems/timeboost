use anyhow::{bail, Result};
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use sailfish::{coordinator::Coordinator, rbc::Rbc, sailfish::sailfish_coordinator};
use sequencer::{
    phase::{
        block_builder::noop::NoOpBlockBuilder, decryption::noop::NoOpDecryptionPhase,
        inclusion::noop::NoOpInclusionPhase, ordering::noop::NoOpOrderingPhase,
    },
    protocol::Sequencer,
};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tide_disco::Url;
use timeboost_utils::PeerConfig;
use tokio::sync::{mpsc::channel, RwLock};
use tracing::{debug, error, info, instrument, warn};
use vbs::version::StaticVersion;

use crate::mempool::Mempool;

use multiaddr::{Multiaddr, PeerId};
use timeboost_core::types::{
    event::{SailfishEventType, TimeboostEventType, TimeboostStatusEvent},
    metrics::{prometheus::PrometheusMetrics, SailfishMetrics, TimeboostMetrics},
    Keypair, NodeId, PublicKey,
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

    /// The mempool for the timeboost node.
    mempool: Arc<RwLock<Mempool>>,
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
            mempool: mempool.clone(),
        }
    }

    #[instrument(level = "info", skip_all, fields(node = %self.id))]
    pub async fn go(
        mut self,
        prom: Arc<PrometheusMetrics>,
        coordinator: &mut Coordinator<Rbc>,
        tb_metrics: TimeboostMetrics,
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

        let sequencer = Sequencer::new(
            NoOpInclusionPhase,
            NoOpDecryptionPhase,
            NoOpOrderingPhase,
            NoOpBlockBuilder,
            tb_metrics,
            self.mempool.clone(),
        );

        // Start the sequencer.
        tokio::spawn(sequencer.go(self.shutdown_rx.clone(), self.app_tx.clone()));

        // Start the block producer.
        let (producer, p_tx) = producer::Producer::new(self.shutdown_rx.clone());
        tokio::spawn(producer.run());

        loop {
            tokio::select! { biased;
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
    let sf_metrics = SailfishMetrics::new(prom.as_ref());
    let tb_metrics = TimeboostMetrics::new(prom.as_ref());
    let (tb_app_tx, tb_app_rx) = channel(100);

    // First, initialize and run the sailfish node.
    let coordinator = &mut sailfish_coordinator(
        id,
        bootstrap_nodes,
        staked_nodes,
        keypair,
        bind_address,
        sf_metrics,
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
    );

    info!("Timeboost is running.");
    timeboost.go(prom, coordinator, tb_metrics).await
}
