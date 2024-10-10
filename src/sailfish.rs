use crate::{
    constants::{EXTERNAL_EVENT_CHANNEL_SIZE, INTERNAL_EVENT_CHANNEL_SIZE},
    message::*,
    tasks::network::NetworkTaskState,
};
use async_broadcast::{broadcast, Receiver, Sender};
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
use hotshot_task::task::{Task, TaskState};
use hotshot_types::{
    network::{Libp2pConfig, NetworkConfig},
    PeerConfig,
};
use libp2p_identity::PeerId;
use libp2p_networking::{
    network::{
        behaviours::dht::record::{Namespace, RecordKey, RecordValue},
        GossipConfig, NetworkNodeConfig,
    },
    reexport::Multiaddr,
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
};
use tokio::task::JoinHandle;
use tracing::{info, span::Record};

pub struct Sailfish {
    /// The public key of the sailfish node.
    public_key: BLSPubKey,

    /// The private key of the sailfish node.
    private_key: BLSPrivKey,

    /// The Libp2p PeerId of the sailfish node.
    peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    bind_address: Multiaddr,

    /// The internal event stream of the sailfish node.
    internal_event_stream: (Sender<Arc<SailfishMessage>>, Receiver<Arc<SailfishMessage>>),

    /// The external event stream of the sailfish node.
    external_event_stream: (Sender<Arc<SailfishMessage>>, Receiver<Arc<SailfishMessage>>),

    /// The background tasks for the sailfish node.
    background_tasks: Vec<JoinHandle<Box<dyn TaskState<Event = SailfishMessage>>>>,

    /// The ID of the sailfish node.
    id: u64,
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
            public_key,
            private_key,
            peer_id,
            bind_address,
            internal_event_stream: broadcast(INTERNAL_EVENT_CHANNEL_SIZE),
            external_event_stream: broadcast(EXTERNAL_EVENT_CHANNEL_SIZE),
            background_tasks: Vec::new(),
            id,
        }
    }

    /// Initialize the networking for the sailfish node.
    ///
    /// # Panics
    /// - If the port cast fails.
    pub async fn initialize_networking(
        &self,
        config: NetworkNodeConfig<BLSPubKey>,
        bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
        staked_nodes: Vec<PeerConfig<BLSPubKey>>,
    ) {
        let mut network_config = NetworkConfig::default();
        network_config.config.known_nodes_with_stake = staked_nodes;
        network_config.libp2p_config = Some(Libp2pConfig {
            bootstrap_nodes: bootstrap_nodes.read().await.clone(),
        });
        network_config.config.known_da_nodes = vec![];

        let libp2p_keypair = derive_libp2p_keypair::<BLSPubKey>(&self.private_key)
            .expect("failed to derive libp2p keypair");

        let record_value = RecordValue::new_signed(
            &RecordKey::new(Namespace::Lookup, self.public_key.to_bytes()),
            libp2p_keypair.public().to_peer_id().to_bytes(),
            &self.private_key,
        )
        .expect("failed to create record value");

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
        .expect("failed to initialize libp2p network");

        info!("Waiting for network to be ready");
        network.wait_for_ready().await;

        info!("Network is ready, starting consensus");
    }

    async fn run_tasks(&mut self) {
        info!("Starting background tasks for Sailfish");
        let network_handle = Task::new(
            NetworkTaskState::new(
                self.internal_event_stream.0.clone(),
                self.internal_event_stream.1.clone(),
            ),
            self.internal_event_stream.0.clone(),
            self.internal_event_stream.1.clone(),
        );

        self.background_tasks.push(network_handle.run());
    }

    pub async fn run(&mut self) {
        tracing::info!("Starting Sailfish Node {}", self.id);
        self.run_tasks().await;
    }
}

fn generate_key_pair(seed: [u8; 32], id: u64) -> (BLSPrivKey, BLSPubKey) {
    let private_key = BLSPubKey::generated_from_seed_indexed(seed, id).1;
    let public_key = BLSPubKey::from_private(&private_key);
    (private_key, public_key)
}

pub async fn initialize_and_run_sailfish(
    id: u64,
    network_size: usize,
    to_connect_addrs: HashSet<(PeerId, Multiaddr)>,
) {
    let seed = [0u8; 32];

    let (private_key, public_key) = generate_key_pair(seed, id);
    let libp2p_keypair =
        derive_libp2p_keypair::<BLSPubKey>(&private_key).expect("failed to derive libp2p keypair");
    let mut sailfish = Sailfish::new(public_key, private_key, id);

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

    let network_config = NetworkNodeConfigBuilder::default()
        .keypair(libp2p_keypair)
        .replication_factor(replication_factor)
        .bind_address(Some(bind_address))
        .to_connect_addrs(to_connect_addrs)
        .republication_interval(None)
        .build()
        .expect("Failed to build network node config");

    let bootstrap_nodes = Arc::new(RwLock::new(vec![]));
    let staked_nodes = vec![];

    sailfish
        .initialize_networking(network_config, bootstrap_nodes, staked_nodes)
        .await;

    sailfish.run().await;
}
