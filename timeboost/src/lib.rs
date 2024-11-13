use anyhow::Result;
use api::endpoints::TimeboostApiState;
use std::{collections::HashSet, sync::Arc};
use tide_disco::Url;
use tokio::{signal, sync::mpsc::channel};
use tracing::{error, info, warn};

use hotshot_types::{traits::metrics::Metrics, PeerConfig};
use multiaddr::{Multiaddr, PeerId};
use sailfish::sailfish::run_sailfish;
use timeboost_core::types::{
    event::{SailfishStatusEvent, TimeboostStatusEvent},
    metrics::ConsensusMetrics,
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
}

impl Timeboost {
    pub fn new(
        id: NodeId,
        port: u16,
        app_rx: Receiver<SailfishStatusEvent>,
        app_tx: Sender<TimeboostStatusEvent>,
    ) -> Self {
        Self {
            id,
            timeboost_port: port,
            app_rx,
            app_tx,
        }
    }

    pub async fn go(mut self) -> Result<()> {
        tokio::spawn(async move {
            let api = TimeboostApiState::new(self.app_tx.clone());
            if let Err(e) = api
                .run(Url::parse(&format!("http://0.0.0.0:{}", self.timeboost_port)).unwrap())
                .await
            {
                error!("Failed to run timeboost api: {}", e);
            }
        });

        tokio::select! {
            event = self.app_rx.recv() => {
                info!("Received event: {:?}", event);
            }
            _ = signal::ctrl_c() => {
                warn!("Received termination signal, shutting down...");
            }
        }

        Ok(())
    }
}

pub async fn run_timeboost(
    id: NodeId,
    timeboost_port: u16,
    timeboost_rpc_port: u16,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
) -> Result<()> {
    info!("Starting timeboost");

    let metrics = Arc::new(ConsensusMetrics::new(Metrics));

    // The application layer will broadcast events to the timeboost node.
    let (sf_app_tx, sf_app_rx) = channel(100);

    let (tb_app_tx, tb_app_rx) = channel(100);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
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
        )
        .await
    });

    // Spawn the RPC api.
    let api_tx = tb_app_tx.clone();
    tokio::spawn(async move {
        let api = TimeboostApiState::new(api_tx);
        api.run(Url::parse(&format!("http://0.0.0.0:{}", timeboost_rpc_port)).unwrap())
            .await
            .unwrap();
    });

    // Then, initialize and run the timeboost node.
    let timeboost = Timeboost::new(id, timeboost_port, sf_app_rx, tb_app_tx);

    info!("Timeboost is running.");
    timeboost.go().await
}
