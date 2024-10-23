use crate::{
    consensus::{committee::StaticCommittee, Consensus, TaskContext},
    coordinator::Coordinator,
};
use async_lock::RwLock;
use hotshot::{
    traits::{
        implementations::{
            derive_libp2p_keypair, derive_libp2p_multiaddr, derive_libp2p_peer_id,
            Libp2pMetricsValue, Libp2pNetwork,
        },
        NetworkNodeConfigBuilder,
    },
    types::{BLSPrivKey, BLSPubKey, SignatureKey},
};
use hotshot_types::{
    data::ViewNumber,
    network::{Libp2pConfig, NetworkConfig},
    traits::node_implementation::ConsensusTime,
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
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{info, instrument};

pub struct Sailfish {
    /// The ID of the sailfish node.
    pub id: u64,

    /// The public key of the sailfish node.
    pub public_key: BLSPubKey,

    /// The private key of the sailfish node.
    pub private_key: BLSPrivKey,

    /// The Libp2p PeerId of the sailfish node.
    pub peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    pub bind_address: Multiaddr,

    /// The coordinator of the sailfish node.
    pub coordinator: Option<Coordinator>,
}

impl Sailfish {
    pub fn new(
        id: u64,
        public_key: BLSPubKey,
        private_key: BLSPrivKey,
        bind_address: Multiaddr,
        peer_id: PeerId,
    ) -> Self {
        Sailfish {
            id,
            public_key,
            private_key,
            peer_id,
            bind_address,
            coordinator: None,
        }
    }

    /// Initialize the networking for the sailfish node.
    #[instrument(
        skip_all,
        fields(id = self.id)
    )]
    pub async fn init(
        &mut self,
        config: NetworkNodeConfig<BLSPubKey>,
        bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
        staked_nodes: Vec<PeerConfig<BLSPubKey>>,
    ) {
        let mut network_config = NetworkConfig::default();
        network_config.config.known_nodes_with_stake = staked_nodes.clone();
        network_config.libp2p_config = Some(Libp2pConfig {
            bootstrap_nodes: bootstrap_nodes.read().await.clone(),
        });

        // We don't have any DA nodes in Sailfish.
        network_config.config.known_da_nodes = vec![];

        let libp2p_keypair = derive_libp2p_keypair::<BLSPubKey>(&self.private_key)
            .expect("Failed to derive libp2p keypair");

        let record_value = RecordValue::new_signed(
            &RecordKey::new(Namespace::Lookup, self.public_key.to_bytes()),
            libp2p_keypair.public().to_peer_id().to_bytes(),
            &self.private_key,
        )
        .expect("Failed to create record value");

        // Create the Libp2p network
        let network = Libp2pNetwork::new(
            Libp2pMetricsValue::default(),
            config,
            self.public_key,
            record_value,
            bootstrap_nodes,
            usize::try_from(self.id).expect("id is too large"),
            false,
        )
        .await
        .expect("Failed to initialize libp2p network");

        network.wait_for_ready().await;
        info!("Network is ready.");

        let quorum_membership = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|node| node.stake_table_entry.stake_key)
                .collect::<Vec<_>>(),
        );

        let consensus = Consensus::new(
            TaskContext {
                id: self.id,
                round: ViewNumber::genesis(),
                public_key: self.public_key,
                private_key: self.private_key.clone(),
            },
            quorum_membership,
        );

        self.coordinator = Some(Coordinator::new(self.id, Box::new(network), consensus));
    }

    #[instrument(
        skip_all,
        target = "run",
        fields(id = self.id)
    )]
    pub async fn run(self) {
        tracing::info!("Starting Sailfish Node {}", self.id);
        self.coordinator
            .expect("The Coordinator not initialized; Please call init() first!")
            .run()
            .await
    }
}

pub fn generate_key_pair(seed: [u8; 32], id: u64) -> (BLSPrivKey, BLSPubKey) {
    let private_key = BLSPubKey::generated_from_seed_indexed(seed, id).1;
    let public_key = BLSPubKey::from_private(&private_key);
    (private_key, public_key)
}

/// Initializes and runs a Sailfish node.
///
/// # Arguments
///
/// * `id` - Node identifier.
/// * `network_size` - Size of the network.
/// * `to_connect_addrs` - Addresses to connect to at initialization.
/// * `staked_nodes` - Configurations of staked nodes.
/// * `validator_config` - The validator config for the sailfish node.
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
pub async fn initialize_and_run_sailfish(
    id: u64,
    network_size: usize,
    to_connect_addrs: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<BLSPubKey>>,
) {
    let seed = [0u8; 32];

    let (private_key, public_key) = generate_key_pair(seed, id);
    let libp2p_keypair =
        derive_libp2p_keypair::<BLSPubKey>(&private_key).expect("failed to derive libp2p keypair");

    let peer_id =
        derive_libp2p_peer_id::<BLSPubKey>(&private_key).expect("failed to derive libp2p peer id");

    let bind_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (8000 + id)
            .try_into()
            .expect("failed to create advertise address due to invalid port cast"),
    )
    .to_string();

    let bind_address =
        derive_libp2p_multiaddr(&bind_address).expect("failed to derive libp2p multiaddr");

    let mut sailfish = Sailfish::new(id, public_key, private_key, bind_address.clone(), peer_id);

    let replication_factor =
        NonZeroUsize::new((2 * network_size).div_ceil(3)).expect("network size must be non-zero");

    let network_config = NetworkNodeConfigBuilder::default()
        .keypair(libp2p_keypair)
        .replication_factor(replication_factor)
        .bind_address(Some(bind_address))
        .to_connect_addrs(to_connect_addrs.clone())
        .republication_interval(None)
        .build()
        .expect("Failed to build network node config");

    let bootstrap_nodes = Arc::new(RwLock::new(
        to_connect_addrs
            .into_iter()
            .collect::<Vec<(PeerId, Multiaddr)>>(),
    ));

    sailfish
        .init(network_config, bootstrap_nodes, staked_nodes)
        .await;

    sailfish.run().await;
}
