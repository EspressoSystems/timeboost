use crate::{
    consensus::{committee::StaticCommittee, Consensus, TaskContext},
    constants::EXTERNAL_EVENT_CHANNEL_SIZE,
    coordinator::Coordinator,
    net::Network,
    types::message::SailfishEvent,
};
use async_broadcast::{broadcast, Receiver, Sender};
use async_lock::RwLock;
use hotshot::{
    traits::{
        implementations::{
            derive_libp2p_keypair, derive_libp2p_multiaddr, derive_libp2p_peer_id,
            Libp2pMetricsValue, Libp2pNetwork,
        },
        NetworkError, NetworkNodeConfigBuilder,
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
    /// The id of the sailfish node.
    pub id: u64,

    /// The public key of the sailfish node.
    pub public_key: BLSPubKey,

    /// The private key of the sailfish node.
    pub private_key: BLSPrivKey,

    /// The Libp2p PeerId of the sailfish node.
    pub peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    pub bind_address: Multiaddr,

    /// The external event stream of the sailfish node.
    pub external_event_stream: (Sender<SailfishEvent>, Receiver<SailfishEvent>),
}

impl Sailfish {
    pub fn new(public_key: BLSPubKey, private_key: BLSPrivKey, id: u64) -> Self {
        // Create the bind address for the sailfish node. The panic here should, essentially, never trigger.
        let bind_address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            (8000 + id)
                .try_into()
                .expect("failed to create advertise address due to invalid port cast"),
        )
        .to_string();

        let bind_address =
            derive_libp2p_multiaddr(&bind_address).expect("failed to derive libp2p multiaddr");

        let peer_id = derive_libp2p_peer_id::<BLSPubKey>(&private_key)
            .expect("failed to derive libp2p peer id");

        Sailfish {
            id,
            public_key,
            private_key,
            peer_id,
            bind_address,
            external_event_stream: broadcast(EXTERNAL_EVENT_CHANNEL_SIZE),
        }
    }

    /// Initialize the networking for the sailfish node and run.
    ///
    /// # Panics
    /// - If the port cast fails.
    #[instrument(
        skip_all,
        fields(id = self.id)
    )]
    pub async fn initialize<N: Network<Err = NetworkError> + Send + 'static>(
        self,
        staked_nodes: Vec<PeerConfig<BLSPubKey>>,
        mut network: N,
    ) -> Coordinator {
        let quorum_membership = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|node| *node.stake_table_entry.key())
                .collect(),
        );

        let consensus = Consensus::new(
            TaskContext {
                id: self.id,
                round_number: ViewNumber::genesis(),
                public_key: self.public_key,
                private_key: self.private_key.clone(),
            },
            quorum_membership,
        );

        let coordinator = Coordinator::new(self.id, Box::new(network), consensus);

        info!("Sailfish node {} is ready.", self.id);
        coordinator
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

    let bind_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (8000 + id)
            .try_into()
            .expect("failed to create advertise address due to invalid port cast"),
    )
    .to_string();

    let bind_address =
        derive_libp2p_multiaddr(&bind_address).expect("failed to derive libp2p multiaddr");

    let replication_factor =
        NonZeroUsize::new((2 * network_size).div_ceil(3)).expect("network size must be non-zero");

    let network_node_config = NetworkNodeConfigBuilder::default()
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

    let mut network_config = NetworkConfig::default();
    network_config.config.known_nodes_with_stake = staked_nodes.clone();
    network_config.libp2p_config = Some(Libp2pConfig {
        bootstrap_nodes: bootstrap_nodes.read().await.clone(),
    });

    // We don't have any DA nodes in Sailfish.
    network_config.config.known_da_nodes = vec![];

    let libp2p_keypair =
        derive_libp2p_keypair::<BLSPubKey>(&private_key).expect("failed to derive libp2p keypair");

    let record_value = RecordValue::new_signed(
        &RecordKey::new(Namespace::Lookup, public_key.to_bytes()),
        libp2p_keypair.public().to_peer_id().to_bytes(),
        &private_key,
    )
    .expect("failed to create record value");

    // Create the Libp2p network
    let network = Box::new(
        Libp2pNetwork::new(
            Libp2pMetricsValue::default(),
            network_node_config,
            public_key,
            record_value,
            bootstrap_nodes,
            id.try_into().expect("id is too large"),
            false,
        )
        .await
        .expect("failed to initialize libp2p network"),
    );

    let coordinator = Sailfish::new(public_key, private_key, id)
        .initialize(staked_nodes, network)
        .await;

    coordinator.go().await;
}
