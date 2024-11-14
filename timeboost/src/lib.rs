use anyhow::Result;
use api::endpoints::TimeboostApiState;
use async_channel::bounded;
use std::{collections::HashSet, sync::Arc};
use tide_disco::Url;
use tokio::{
    signal,
    sync::{mpsc::channel, oneshot},
};
use tracing::{error, info, warn};

use hotshot_types::PeerConfig;
use multiaddr::{Multiaddr, PeerId};
use sailfish::sailfish::{run_sailfish, ShutdownToken};
use timeboost_core::types::{
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    metrics::{prometheus::Prometheus, ConsensusMetrics},
    Keypair, NodeId, PublicKey,
};
use tokio::sync::mpsc::{Receiver, Sender};

pub mod api;
pub mod config;
pub mod contracts;

pub struct Timeboost {
    #[allow(unused)]
    id: NodeId,

    #[allow(unused)]
    timeboost_port: u16,

    /// The receiver for events from the sailfish node.
    app_rx: Receiver<SailfishStatusEvent>,

    /// The sender for events to the sailfish node.
    app_tx: Sender<TimeboostStatusEvent>,

    /// The receiver for the shutdown signal.
    shutdown_rx: async_channel::Receiver<ShutdownToken>,
}

impl Timeboost {
    pub fn new(
        id: NodeId,
        port: u16,
        app_rx: Receiver<SailfishStatusEvent>,
        app_tx: Sender<TimeboostStatusEvent>,
        shutdown_rx: async_channel::Receiver<ShutdownToken>,
    ) -> Self {
        Self {
            id,
            timeboost_port: port,
            app_rx,
            app_tx,
            shutdown_rx,
        }
    }

    pub async fn go(mut self) -> Result<ShutdownToken> {
        tokio::spawn(async move {
            let api = TimeboostApiState::new(self.app_tx.clone());
            if let Err(e) = api
                .run(Url::parse(&format!("http://0.0.0.0:{}", self.timeboost_port)).unwrap())
                .await
            {
                error!("Failed to run timeboost api: {}", e);
            }
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
                token = self.shutdown_rx.recv() => {
                    warn!("Received shutdown signal; shutting down.");
                    return token.map_err(|_| anyhow::anyhow!("Failed to receive shutdown signal"));
                }
            }
        }
    }
}

pub async fn run_timeboost(
    id: NodeId,
    _timeboost_port: u16,
    timeboost_rpc_port: u16,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
) -> Result<ShutdownToken> {
    info!("Starting timeboost");

    let metrics = Arc::new(ConsensusMetrics::new(Prometheus::default()));

    // The application layer will broadcast events to the timeboost node.
    let (sf_app_tx, sf_app_rx) = channel(100);

    let (tb_app_tx, tb_app_rx) = channel(100);

    let (shutdown_tx, shutdown_rx) = bounded(1);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
    let sf_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        run_sailfish(
            id,
            bootstrap_nodes,
            staked_nodes,
            keypair,
            bind_address,
            sf_app_tx,
            tb_app_rx,
            metrics,
            shutdown_tx,
            sf_shutdown_rx,
        )
        .await
    });

    // Then, initialize and run the timeboost node.
    let timeboost = Timeboost::new(id, timeboost_rpc_port, sf_app_rx, tb_app_tx, shutdown_rx);

    info!("Timeboost is running.");
    timeboost.go().await
}
