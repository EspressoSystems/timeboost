use crate::{
    consensus::Consensus,
    coordinator_helpers::{coordinator::Coordinator, test_coordinator::TestCoordinator},
};

#[cfg(feature = "test")]
use crate::coordinator_helpers::interceptor::NetworkMessageInterceptor;
#[cfg(feature = "test")]
use crate::coordinator_helpers::test_coordinator::CoordinatorAuditEvent;

use anyhow::Result;
use async_lock::RwLock;
use hotshot::{
    traits::{
        implementations::{
            derive_libp2p_keypair, derive_libp2p_peer_id, Libp2pMetricsValue, Libp2pNetwork,
        },
        NetworkNodeConfigBuilder,
    },
    types::SignatureKey,
};
use hotshot_types::{
    network::{Libp2pConfig, NetworkConfig},
    PeerConfig,
};
use libp2p_identity::PeerId;
use libp2p_networking::{
    network::{
        behaviours::dht::record::{Namespace, RecordKey, RecordValue},
        NetworkNodeConfig,
    },
    reexport::Multiaddr,
};
use std::time::Duration;
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        committee::StaticCommittee,
        event::{SailfishStatusEvent, TimeboostStatusEvent},
        Keypair, NodeId, PublicKey,
    },
};
use tokio::signal;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use tracing::{info, instrument};

pub struct Sailfish {
    /// The ID of the sailfish node.
    id: NodeId,

    keypair: Keypair,

    /// The Libp2p PeerId of the sailfish node.
    peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    bind_address: Multiaddr,
}

pub struct ShutdownToken(());

impl ShutdownToken {
    /// This constructor is intentionally private to ensure that only the
    /// code which *creates* the `Coordinator` can create a `ShutdownToken`.
    #[cfg(not(feature = "test"))]
    fn new() -> Self {
        Self(())
    }

    /// This constructor is public for testing purposes so the shutdown token
    /// can be created within tests.
    #[cfg(feature = "test")]
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Sailfish {
    pub fn new<N>(id: N, keypair: Keypair, bind: Multiaddr) -> Result<Self>
    where
        N: Into<NodeId>,
    {
        let peer_id = derive_libp2p_peer_id::<PublicKey>(keypair.private_key())?;
        Ok(Sailfish {
            id: id.into(),
            keypair,
            peer_id,
            bind_address: bind,
        })
    }

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

    pub fn init<C>(
        self,
        comm: C,
        staked_nodes: Vec<PeerConfig<PublicKey>>,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
    ) -> Coordinator<C>
    where
        C: Comm + Send + 'static,
    {
        let committee = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|node| node.stake_table_entry.stake_key)
                .collect::<Vec<_>>(),
        );

        let consensus = Consensus::new(self.id, self.keypair, committee);

        Coordinator::new(self.id, comm, consensus, shutdown_rx, sf_app_tx, tb_app_rx)
    }

    #[cfg(feature = "test")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_test_coordinator<C>(
        self,
        comm: C,
        staked_nodes: Vec<PeerConfig<PublicKey>>,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
        event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
        interceptor: Arc<NetworkMessageInterceptor>,
    ) -> TestCoordinator<C>
    where
        C: Comm + Send + 'static,
    {
        let committee = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|node| node.stake_table_entry.stake_key)
                .collect::<Vec<_>>(),
        );

        let consensus = Consensus::new(self.id, self.keypair, committee);

        TestCoordinator::new(
            self.id,
            comm,
            consensus,
            shutdown_rx,
            sf_app_tx,
            tb_app_rx,
            event_log,
            interceptor,
        )
    }

    pub async fn go(
        self,
        n: Libp2pNetwork<PublicKey>,
        staked_nodes: Vec<PeerConfig<PublicKey>>,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        shutdown_tx: oneshot::Sender<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
    ) -> Result<()> {
        let mut coordinator_handle = tokio::spawn(
            self.init(n, staked_nodes, shutdown_rx, sf_app_tx, tb_app_rx)
                .go(),
        );

        let shutdown_timeout = Duration::from_secs(5);

        tokio::select! {
            coordinator_result = &mut coordinator_handle => {
                tracing::info!("Coordinator task completed");
                coordinator_result?;
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Received termination signal, initiating graceful shutdown...");
                shutdown_tx.send(ShutdownToken::new())
                    .map_err(|_| anyhow::anyhow!("Failed to send shutdown signal"))?;

                // Wait for coordinator to shutdown gracefully or timeout
                match tokio::time::timeout(shutdown_timeout, &mut coordinator_handle).await {
                    Ok(coordinator_result) => {
                        tracing::info!("Coordinator shutdown gracefully");
                        coordinator_result?;
                    }
                    Err(_) => {
                        tracing::warn!("Coordinator did not shutdown within grace period, forcing abort");
                        coordinator_handle.abort();
                    }
                }
            }
        }

        Ok(())
    }
}

/// Initializes and runs a Sailfish node.
///
/// # Arguments
///
/// * `id` - Node identifier.
/// * `port` - Listen port.
/// * `network_size` - Size of the network.
/// * `to_connect_addrs` - Addresses to connect to at initialization.
/// * `staked_nodes` - Configurations of staked nodes.
/// * `validator_config` - The validator config for the sailfish node.
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
pub async fn run_sailfish(
    id: NodeId,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
    sf_app_tx: Sender<SailfishStatusEvent>,
    tb_app_rx: Receiver<TimeboostStatusEvent>,
) -> Result<()> {
    let network_size =
        NonZeroUsize::new(staked_nodes.len()).expect("Network size must be positive");

    let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(keypair.private_key())?;

    let replication_factor = NonZeroUsize::new((2 * network_size.get()).div_ceil(3))
        .expect("ceil(2n/3) with n > 0 never gives 0");

    let network_config = NetworkNodeConfigBuilder::default()
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

    let s = Sailfish::new(id, keypair, bind_address)?;
    let n = s
        .setup_libp2p(network_config, bootstrap_nodes, &staked_nodes)
        .await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    s.go(
        n,
        staked_nodes,
        shutdown_rx,
        shutdown_tx,
        sf_app_tx,
        tb_app_rx,
    )
    .await
}
