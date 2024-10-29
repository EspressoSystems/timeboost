use crate::{comm::Comm, consensus::Consensus, coordinator::Coordinator};

#[cfg(feature = "test")]
use crate::coordinator::CoordinatorAuditEvent;

use anyhow::Result;
use async_lock::RwLock;
use hotshot::{
    traits::{
        implementations::{
            derive_libp2p_keypair, derive_libp2p_multiaddr, derive_libp2p_peer_id,
            Libp2pMetricsValue, Libp2pNetwork,
        },
        NetworkError, NetworkNodeConfigBuilder,
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
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};
use timeboost_core::types::{committee::StaticCommittee, NodeId, PrivateKey, PublicKey};
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{info, instrument};

pub struct Sailfish {
    /// The ID of the sailfish node.
    id: NodeId,

    /// The public key of the sailfish node.
    public_key: PublicKey,

    /// The private key of the sailfish node.
    private_key: PrivateKey,

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
    pub fn new<N>(
        id: N,
        public_key: PublicKey,
        private_key: PrivateKey,
        bind: Multiaddr,
    ) -> Result<Self>
    where
        N: Into<NodeId>,
    {
        let peer_id = derive_libp2p_peer_id::<PublicKey>(&private_key)?;
        Ok(Sailfish {
            id: id.into(),
            public_key,
            private_key,
            peer_id,
            bind_address: bind,
        })
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[cfg(feature = "test")]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn bind_addr(&self) -> &Multiaddr {
        &self.bind_address
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

        let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(&self.private_key)?;

        let record_value = RecordValue::new_signed(
            &RecordKey::new(Namespace::Lookup, self.public_key.to_bytes()),
            libp2p_keypair.public().to_peer_id().to_bytes(),
            &self.private_key,
        )?;

        // Create the Libp2p network
        let network = Libp2pNetwork::new(
            Libp2pMetricsValue::default(),
            config,
            self.public_key,
            record_value,
            bootstrap_nodes,
            u64::from(self.id) as usize,
            false,
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
        #[cfg(feature = "test")] event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    ) -> Coordinator
    where
        C: Comm<Err = NetworkError> + Send + 'static,
    {
        let quorum_membership = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|node| node.stake_table_entry.stake_key)
                .collect::<Vec<_>>(),
        );

        let consensus = Consensus::new(
            self.id,
            self.public_key,
            self.private_key,
            quorum_membership,
        );

        Coordinator::new(
            self.id,
            comm,
            consensus,
            shutdown_rx,
            #[cfg(feature = "test")]
            event_log,
        )
    }
}

pub fn generate_key_pair(seed: [u8; 32], id: u64) -> (PrivateKey, PublicKey) {
    let private_key = PublicKey::generated_from_seed_indexed(seed, id).1;
    let public_key = PublicKey::from_private(&private_key);
    (private_key, public_key)
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
pub async fn run(
    id: NodeId,
    port: u16,
    network_size: NonZeroUsize,
    to_connect_addrs: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
) -> Result<()> {
    let seed = [0u8; 32];

    let (private_key, public_key) = generate_key_pair(seed, id.into());
    let libp2p_keypair = derive_libp2p_keypair::<PublicKey>(&private_key)?;
    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{port}"))?;

    let replication_factor = NonZeroUsize::new((2 * network_size.get()).div_ceil(3))
        .expect("ceil(2n/3) with n > 0 never gives 0");

    let network_config = NetworkNodeConfigBuilder::default()
        .keypair(libp2p_keypair)
        .replication_factor(replication_factor)
        .bind_address(Some(bind_address.clone()))
        .to_connect_addrs(to_connect_addrs.clone())
        .republication_interval(None)
        .build()?;

    let bootstrap_nodes = Arc::new(RwLock::new(
        to_connect_addrs
            .into_iter()
            .collect::<Vec<(PeerId, Multiaddr)>>(),
    ));

    let s = Sailfish::new(id, public_key, private_key, bind_address)?;
    let n = s
        .setup_libp2p(network_config, bootstrap_nodes, &staked_nodes)
        .await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let coordinator_handle = tokio::spawn(s.init(n, staked_nodes, shutdown_rx, None).go());

    tokio::select! {
        _ = coordinator_handle => {}
        _ = signal::ctrl_c() => {
            tracing::info!("Received termination signal, shutting down...");
            shutdown_tx.send(ShutdownToken::new()).map_err(|_| anyhow::anyhow!("Failed to send shutdown signal"))?;
        }
    }

    Ok(())
}
