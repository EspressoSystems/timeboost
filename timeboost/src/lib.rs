use anyhow::{bail, Result};
use api::{endpoints::TimeboostApiState, metrics::serve_metrics_api};
use sailfish::{
    coordinator::Coordinator,
    rbc::Rbc,
    sailfish::{Sailfish, SailfishInitializerBuilder},
};
use sequencer::{
    phase::{
        block_builder::noop::NoOpBlockBuilder, decryption::noop::NoOpDecryptionPhase,
        inclusion::noop::NoOpInclusionPhase, ordering::noop::NoOpOrderingPhase,
    },
    protocol::Sequencer,
};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tide_disco::Url;
use timeboost_networking::network::client::{derive_libp2p_peer_id, Libp2pInitializer};
use timeboost_utils::PeerConfig;
use tokio::{sync::mpsc::channel, task::JoinHandle};
use tracing::{debug, error, instrument, warn};
use vbs::version::StaticVersion;

use crate::mempool::Mempool;

use multiaddr::{Multiaddr, PeerId};
use multisig::{Committee, Keypair, PublicKey};
use timeboost_core::{
    traits::has_initializer::HasInitializer,
    types::{
        event::{SailfishEventType, TimeboostEventType, TimeboostStatusEvent},
        metrics::{prometheus::PrometheusMetrics, SailfishMetrics, TimeboostMetrics},
        NodeId,
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

pub struct TimeboostInitializer {
    /// The ID of the node.
    pub id: NodeId,

    /// The port to bind the RPC server to.
    pub rpc_port: u16,

    /// The port to bind the metrics API server to.
    pub metrics_port: u16,

    /// The bootstrap nodes to connect to.
    pub bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,

    /// The staked nodes to join the committee with.
    pub staked_nodes: Vec<PeerConfig<PublicKey>>,

    /// The keypair for the node.
    pub keypair: Keypair,

    /// The bind address for the node.
    pub bind_address: Multiaddr,

    /// The receiver for the shutdown signal.
    pub shutdown_rx: watch::Receiver<()>,
}

pub struct Timeboost {
    /// The ID of the node.
    id: NodeId,

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
    mempool: Arc<Mempool>,

    /// The coordinator for the timeboost node.
    coordinator: Coordinator<Rbc>,

    /// The prometheus metrics for all the metrics layers.
    metrics: Arc<PrometheusMetrics>,

    /// The timeboost metrics layer.
    tb_metrics: TimeboostMetrics,
}

#[async_trait::async_trait]
impl HasInitializer for Timeboost {
    type Initializer = TimeboostInitializer;
    type Into = Self;

    async fn initialize(initializer: Self::Initializer) -> Result<Self> {
        let prom = Arc::new(PrometheusMetrics::default());
        let sf_metrics = SailfishMetrics::new(prom.as_ref());
        let tb_metrics = TimeboostMetrics::new(prom.as_ref());
        let (tb_app_tx, tb_app_rx) = channel(100);

        // Make the network.
        let network = Libp2pInitializer::new(
            &initializer.keypair.secret_key(),
            initializer.staked_nodes.clone(),
            initializer.bootstrap_nodes.clone(),
            initializer.bind_address.clone(),
        )?
        .into_network(
            u64::from(initializer.id) as usize,
            initializer.keypair.public_key(),
            initializer.keypair.secret_key(),
        )
        .await?;
        network.wait_for_ready().await;

        let peer_id = derive_libp2p_peer_id::<PublicKey>(&initializer.keypair.secret_key())?;

        let committee = Committee::new(
            initializer
                .staked_nodes
                .iter()
                .enumerate()
                .map(|(i, cfg)| (i as u8, cfg.stake_table_entry.stake_key)),
        );
        let rbc = Rbc::new(network, initializer.keypair.clone(), committee.clone());

        let sailfish_initializer = SailfishInitializerBuilder::default()
            .id(initializer.id)
            .keypair(initializer.keypair)
            .bind_address(initializer.bind_address)
            .network(rbc)
            .committee(committee.clone())
            .metrics(sf_metrics)
            .peer_id(peer_id)
            .build()
            .expect("sailfish initializer to be built");
        let sailfish = Sailfish::initialize(sailfish_initializer).await.unwrap();
        let coordinator = sailfish.into_coordinator();

        let mempool = Arc::new(Mempool::new());

        // Then, initialize and run the timeboost node.
        let timeboost = Timeboost {
            id: initializer.id,
            rpc_port: initializer.rpc_port,
            metrics_port: initializer.metrics_port,
            app_tx: tb_app_tx,
            app_rx: tb_app_rx,
            shutdown_rx: initializer.shutdown_rx,
            mempool,
            coordinator,
            metrics: prom,
            tb_metrics,
        };

        Ok(timeboost)
    }
}

impl Timeboost {
    async fn start_rpc_api(app_tx: Sender<TimeboostStatusEvent>, rpc_port: u16) -> JoinHandle<()> {
        tokio::spawn(async move {
            let api = TimeboostApiState::new(app_tx);
            if let Err(e) = api
                .run(Url::parse(&format!("http://0.0.0.0:{}", rpc_port)).unwrap())
                .await
            {
                error!("failed to run timeboost api: {}", e);
            }
        })
    }

    async fn start_metrics_api(
        metrics: Arc<PrometheusMetrics>,
        metrics_port: u16,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            serve_metrics_api::<StaticVersion<0, 1>>(metrics_port, metrics).await
        })
    }

    #[instrument(level = "info", skip_all, fields(node = %self.id))]
    pub async fn go(mut self, committee_size: usize) -> Result<()> {
        let app_tx = self.app_tx.clone();
        let rpc_handle = Self::start_rpc_api(app_tx, self.rpc_port).await;
        let metrics_handle = Self::start_metrics_api(self.metrics, self.metrics_port).await;

        // Kickstart the network.
        match self.coordinator.start().await {
            Ok(actions) => {
                for a in actions {
                    let _ = self.coordinator.execute(a).await;
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
            self.tb_metrics,
            self.mempool.clone(),
        );

        // Start the sequencer.
        let sequencer_handle = tokio::spawn(sequencer.go(
            self.shutdown_rx.clone(),
            self.app_tx.clone(),
            committee_size,
        ));

        // Start the block producer.
        let (producer, p_tx) = producer::Producer::new(self.shutdown_rx.clone());
        tokio::spawn(producer.run());

        loop {
            tokio::select! { biased;
                result = self.coordinator.next() => match result {
                    Ok(actions) => {
                        for a in actions {
                            let event = self.coordinator.execute(a).await;
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
                                self.coordinator.handle_transactions(transactions);
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

                    warn!("shutting down sequencer");
                    sequencer_handle.abort();

                    warn!("shutting down coordinator");
                    self.coordinator.shutdown().await.expect("shutdown coordinator");

                    result.expect("the shutdown sender was dropped before the receiver could receive the token");
                    return Ok(());
                }
            }
        }
    }
}
