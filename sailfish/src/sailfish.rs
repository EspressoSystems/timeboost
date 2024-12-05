use crate::rbc::Rbc;
use crate::{consensus::Consensus, coordinator::Coordinator};

use anyhow::Result;
use async_lock::RwLock;
use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};
use timeboost_core::{
    traits::comm::Comm,
    types::{committee::StaticCommittee, metrics::SailfishMetrics, Keypair, NodeId, PublicKey},
};
use timeboost_crypto::traits::signature_key::SignatureKey;
use timeboost_networking::network::{
    behaviours::dht::record::{Namespace, RecordKey, RecordValue},
    client::{derive_libp2p_keypair, derive_libp2p_peer_id, Libp2pMetricsValue, Libp2pNetwork},
    NetworkNodeConfig, NetworkNodeConfigBuilder,
};
use timeboost_utils::{
    types::config::{Libp2pConfig, NetworkConfig},
    PeerConfig,
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
        metrics: Arc<SailfishMetrics>,
    ) -> Coordinator<C>
    where
        C: Comm + Send + 'static,
    {
        let committee = StaticCommittee::from(&*staked_nodes);
        let consensus = Consensus::new(self.id, self.keypair, committee).with_metrics(metrics);

        Coordinator::new(self.id, comm, consensus)
    }
}

/// Initializes and returns sailfish coordinator
///
/// # Arguments
///
/// * `id` - Node identifier.
/// * `bootstrap_nodes` - Libp2p bootstrap nodes.
/// * `staked_nodes` - Configurations of staked nodes.
/// * `keypair` - Libp2p keypair.
/// * `bind_address` - Addresses to bind to.
/// * `metrics` - Sailfish metrics
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
pub async fn sailfish_coordinator(
    id: NodeId,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
    metrics: Arc<SailfishMetrics>,
) -> Coordinator<Rbc> {
    let network_size =
        NonZeroUsize::new(staked_nodes.len()).expect("network size must be positive");

    let libp2p_keypair =
        derive_libp2p_keypair::<PublicKey>(keypair.private_key()).expect("Keypair to derive");

    let replication_factor = NonZeroUsize::new((2 * network_size.get()).div_ceil(3))
        .expect("ceil(2n/3) with n > 0 never gives 0");
    let network_config = NetworkNodeConfigBuilder::default()
        .keypair(libp2p_keypair)
        .replication_factor(replication_factor)
        .bind_address(Some(bind_address.clone()))
        .to_connect_addrs(bootstrap_nodes.clone())
        .republication_interval(None)
        .build()
        .expect("Network config to be built");

    let bootstrap_nodes = Arc::new(RwLock::new(
        bootstrap_nodes
            .into_iter()
            .collect::<Vec<(PeerId, Multiaddr)>>(),
    ));

    let s = Sailfish::new(id, keypair, bind_address).expect("setup failed");
    let n = s
        .setup_libp2p(network_config, bootstrap_nodes, &staked_nodes)
        .await
        .expect("Libp2p network setup");

    let rbc = Rbc::new(n, s.keypair.clone(), StaticCommittee::from(&*staked_nodes));

    s.init(rbc, staked_nodes, metrics)
}
