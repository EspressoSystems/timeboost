use crate::{
    consensus::{Consensus, ConsensusState},
    coordinator::Coordinator,
};

#[cfg(feature = "test")]
use crate::coordinator::CoordinatorAuditEvent;

use anyhow::{bail, Context, Result};
use async_lock::RwLock;
use hotshot::types::SignatureKey;
use hotshot_types::{
    network::{Libp2pConfig, NetworkConfig},
    PeerConfig,
};
use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use std::time::Duration;
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        committee::StaticCommittee,
        event::{SailfishStatusEvent, TimeboostStatusEvent},
        metrics::ConsensusMetrics,
        Keypair, NodeId, PublicKey,
    },
};
use timeboost_networking::network::{
    behaviours::dht::record::{Namespace, RecordKey, RecordValue},
    client::{derive_libp2p_keypair, derive_libp2p_peer_id, Libp2pMetricsValue, Libp2pNetwork},
    NetworkNodeConfig, NetworkNodeConfigBuilder,
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;
use tracing::{info, instrument};

pub async fn make_libp2p_network(
    id: NodeId,
    staked_nodes: &[PeerConfig<PublicKey>],
    keypair: Keypair,
    bind_address: Multiaddr,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
) -> Result<Libp2pNetwork<PublicKey>> {
    let private_key = keypair.private_key();
    let public_key = keypair.public_key();

    let network_size =
        NonZeroUsize::new(staked_nodes.len()).expect("network size must be positive");

    let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(private_key)?;

    let replication_factor = NonZeroUsize::new((2 * network_size.get()).div_ceil(3))
        .expect("ceil(2n/3) with n > 0 never gives 0");

    let network_node_config = NetworkNodeConfigBuilder::default()
        .keypair(libp2p_keypair)
        .replication_factor(replication_factor)
        .bind_address(Some(bind_address.clone()))
        .to_connect_addrs(bootstrap_nodes.clone())
        .republication_interval(None)
        .build()?;

    let bootstrap_nodes = Arc::new(RwLock::new(
        bootstrap_nodes
            .into_iter()
            .collect::<Vec<(PeerId, Multiaddr)>>(),
    ));

    let mut network_config = NetworkConfig::default();
    network_config.config.known_nodes_with_stake = staked_nodes.to_vec();
    network_config.libp2p_config = Some(Libp2pConfig {
        bootstrap_nodes: bootstrap_nodes.read().await.clone(),
    });

    // We don't have any DA nodes in Sailfish.
    network_config.config.known_da_nodes = vec![];

    let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(private_key)?;

    let record_value = RecordValue::new_signed(
        &RecordKey::new(Namespace::Lookup, public_key.to_bytes()),
        libp2p_keypair.public().to_peer_id().to_bytes(),
        private_key,
    )?;

    // Create the Libp2p network
    let mut network = Libp2pNetwork::new(
        Libp2pMetricsValue::default(),
        network_node_config,
        *public_key,
        record_value,
        bootstrap_nodes,
        u64::from(id) as usize,
    )
    .await?;

    network.start().await?;

    info!("Network is ready.");
    Ok(network)
}

#[derive(derive_builder::Builder, custom_debug::Debug)]
#[builder(pattern = "owned")]
pub struct SailfishConfig<C: Comm + Send + 'static> {
    /// The ID of the sailfish node.
    id: NodeId,

    /// The keypair of the sailfish node.
    keypair: Keypair,

    /// The application event stream sender.
    app_tx: Sender<SailfishStatusEvent>,

    /// The application event stream receiver.
    app_rx: Receiver<TimeboostStatusEvent>,

    /// The metrics registry.
    metrics: Arc<ConsensusMetrics>,

    /// The network of the sailfish node.
    net: C,

    /// The consensus state of the sailfish node.
    state: ConsensusState,

    /// The committee of the sailfish node.
    committee: StaticCommittee,

    /// The event log of the sailfish node.
    #[cfg(feature = "test")]
    event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
}

impl<C: Comm + Send + 'static> SailfishConfig<C> {
    pub fn build(self) -> Result<Coordinator<C>> {
        let consensus = Consensus::new(
            self.id,
            self.keypair.clone(),
            self.committee,
            self.metrics,
            self.state,
        );

        Ok(Coordinator::new(
            self.id,
            self.keypair,
            self.net,
            consensus,
            self.app_tx,
            self.app_rx,
            #[cfg(feature = "test")]
            self.event_log,
        ))
        // Ok(
        //     Sailfish::new(self.id, self.keypair, self.bind_address)?.into_coordinator(
        //         self.net,
        //         self.app_tx,
        //         self.app_rx,
        //         self.metrics,
        //         self.state,
        //         self.committee,
        //         #[cfg(feature = "test")]
        //         None,
        //     ),
        // )
    }
}

pub struct Sailfish {
    /// The ID of the sailfish node.
    id: NodeId,

    /// The keypair of the sailfish node.
    keypair: Keypair,

    /// The Libp2p PeerId of the sailfish node.
    peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    bind_address: Multiaddr,
}

impl Sailfish {
    // pub fn new<N>(id: N, keypair: Keypair, bind: Multiaddr) -> Result<Self>
    // where
    //     N: Into<NodeId>,
    // {
    //     let peer_id = derive_libp2p_peer_id::<PublicKey>(keypair.private_key())?;
    //     Ok(Sailfish {
    //         id: id.into(),
    //         keypair,
    //         peer_id,
    //         bind_address: bind,
    //     })
    // }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn bind_addr(&self) -> &Multiaddr {
        &self.bind_address
    }

    #[cfg(feature = "test")]
    pub fn derive_libp2p_keypair(&self) -> Result<libp2p_identity::Keypair> {
        derive_libp2p_keypair::<PublicKey>(self.keypair.private_key())
    }

    #[instrument(skip_all, fields(id = u64::from(self.id)))]
    pub async fn setup_libp2p(
        &self,
        config: NetworkNodeConfig<PublicKey>,
        bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
        staked_nodes: &[PeerConfig<PublicKey>],
    ) -> Result<Libp2pNetwork<PublicKey>> {
        let mut network_config = NetworkConfig::default();
        network_config.config.known_nodes_with_stake = staked_nodes.to_vec();
        network_config.libp2p_config = Some(Libp2pConfig {
            bootstrap_nodes: bootstrap_nodes.read().await.clone(),
        });

        // We don't have any DA nodes in Sailfish.
        network_config.config.known_da_nodes = vec![];

        let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(self.keypair.private_key())?;

        let record_value = RecordValue::new_signed(
            &RecordKey::new(Namespace::Lookup, self.keypair.public_key().to_bytes()),
            libp2p_keypair.public().to_peer_id().to_bytes(),
            self.keypair.private_key(),
        )?;

        // Create the Libp2p network
        let network = Libp2pNetwork::new(
            Libp2pMetricsValue::default(),
            config,
            *self.keypair.public_key(),
            record_value,
            bootstrap_nodes,
            u64::from(self.id) as usize,
        )
        .await?;

        network.wait_for_ready().await;

        info!("Network is ready.");
        Ok(network)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn into_coordinator<C>(
        self,
        comm: C,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
        metrics: Arc<ConsensusMetrics>,
        state: ConsensusState,
        committee: StaticCommittee,
        #[cfg(feature = "test")] event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    ) -> Coordinator<C>
    where
        C: Comm + Send + 'static,
    {
        // let committee = StaticCommittee::new(
        //     staked_nodes
        //         .iter()
        //         .map(|node| node.stake_table_entry.stake_key)
        //         .collect::<Vec<_>>(),
        // );

        let consensus = Consensus::new(self.id, self.keypair.clone(), committee, metrics, state);

        Coordinator::new(
            self.id,
            self.keypair.clone(),
            comm,
            consensus,
            sf_app_tx,
            tb_app_rx,
            #[cfg(feature = "test")]
            event_log,
        )
    }

    // #[allow(clippy::too_many_arguments)]
    // pub async fn go(
    //     self,
    //     n: Libp2pNetwork<PublicKey>,
    //     staked_nodes: Vec<PeerConfig<PublicKey>>,
    //     mut shutdown_rx: watch::Receiver<()>,
    //     sf_app_tx: Sender<SailfishStatusEvent>,
    //     tb_app_rx: Receiver<TimeboostStatusEvent>,
    //     metrics: Arc<ConsensusMetrics>,
    //     state: ConsensusState,
    // ) -> Result<()> {
    //     let mut coordinator_handle = tokio::spawn(
    //         self.init(n, staked_nodes, sf_app_tx, tb_app_rx, metrics, state, None)
    //             .go(shutdown_rx.clone()),
    //     );

    //     let shutdown_timeout = Duration::from_secs(5);

    //     tokio::select! {
    //         _ = &mut coordinator_handle => {
    //             bail!("coordinator task shutdown unexpectedly");
    //         }
    //         _ = shutdown_rx.changed() => {
    //             tracing::info!("received termination signal, initiating graceful shutdown");

    //             // Wait for coordinator to shutdown gracefully or timeout
    //             match tokio::time::timeout(shutdown_timeout, &mut coordinator_handle).await {
    //                 Ok(_) => {
    //                     tracing::info!("coordinator exited successfully");
    //                 }
    //                 Err(_) => {
    //                     coordinator_handle.abort();
    //                     bail!("coordinator did not shutdown within grace period, forcing abort");
    //                 }
    //             }
    //         }
    //     }

    //     Ok(())
    // }
}

/// Initializes and runs a Sailfish node.
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
#[allow(clippy::too_many_arguments)]
pub async fn run_sailfish(
    id: NodeId,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
    sf_app_tx: Sender<SailfishStatusEvent>,
    tb_app_rx: Receiver<TimeboostStatusEvent>,
    metrics: Arc<ConsensusMetrics>,
    shutdown_rx: watch::Receiver<()>,
    state: ConsensusState,
) -> Result<()> {
    // let network_size =
    //     NonZeroUsize::new(staked_nodes.len()).expect("network size must be positive");

    // let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(keypair.private_key())?;

    // let replication_factor = NonZeroUsize::new((2 * network_size.get()).div_ceil(3))
    //     .expect("ceil(2n/3) with n > 0 never gives 0");

    // let network_config = NetworkNodeConfigBuilder::default()
    //     .keypair(libp2p_keypair)
    //     .replication_factor(replication_factor)
    //     .bind_address(Some(bind_address.clone()))
    //     .to_connect_addrs(bootstrap_nodes.clone())
    //     .republication_interval(None)
    //     .build()?;

    // let bootstrap_nodes = Arc::new(RwLock::new(
    //     bootstrap_nodes
    //         .into_iter()
    //         .collect::<Vec<(PeerId, Multiaddr)>>(),
    // ));

    // let s = Sailfish::new(id, keypair, bind_address)?;
    // let n = s
    //     .setup_libp2p(network_config, bootstrap_nodes, &staked_nodes)
    //     .await?;

    let net = make_libp2p_network(
        id,
        &staked_nodes,
        keypair.clone(),
        bind_address,
        bootstrap_nodes,
    )
    .await?;
    let committee = StaticCommittee::new(
        staked_nodes
            .iter()
            .map(|node| node.stake_table_entry.stake_key)
            .collect::<Vec<_>>(),
    );
    let co = SailfishConfigBuilder::default()
        .id(id)
        .keypair(keypair)
        .app_tx(sf_app_tx)
        .app_rx(tb_app_rx)
        .metrics(metrics)
        .net(net)
        .state(state)
        .committee(committee)
        .build()?
        .build()?;

    co.go(shutdown_rx).await
}
