use crate::{
    constants::{EXTERNAL_EVENT_CHANNEL_SIZE, INTERNAL_EVENT_CHANNEL_SIZE},
    message::*,
    tasks::network::NetworkTaskState,
};
use async_broadcast::{broadcast, Receiver, Sender};
use hotshot::{
    traits::implementations::{derive_libp2p_multiaddr, Libp2pMetricsValue, Libp2pNetwork},
    types::{BLSPrivKey, BLSPubKey},
};
use hotshot_task::task::{Task, TaskState};
use hotshot_types::{
    network::{Libp2pConfig, NetworkConfig},
    PeerConfig,
};
use libp2p_identity::PeerId;
use libp2p_networking::{network::GossipConfig, reexport::Multiaddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

pub struct Sailfish {
    /// The public key of the sailfish node.
    public_key: BLSPubKey,

    /// The private key of the sailfish node.
    private_key: BLSPrivKey,

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
        Sailfish {
            public_key,
            private_key,
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
        bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
        staked_nodes: Vec<PeerConfig<BLSPubKey>>,
    ) {
        // Create the bind address for the sailfish node. The panic here should, essentially, never trigger.
        let bind_address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            (8000 + self.id)
                .try_into()
                .expect("failed to create advertise address due to invalid port cast"),
        )
        .to_string();

        let bind_address =
            derive_libp2p_multiaddr(&bind_address).expect("failed to derive libp2p multiaddr");

        let mut network_config = NetworkConfig::default();
        network_config.config.known_nodes_with_stake = staked_nodes;
        network_config.libp2p_config = Some(Libp2pConfig { bootstrap_nodes });
        network_config.config.known_da_nodes = vec![];

        // Create the Libp2p network
        let network = Libp2pNetwork::from_config(
            network_config,
            GossipConfig::default(),
            bind_address,
            &self.public_key,
            &self.private_key,
            Libp2pMetricsValue::default(),
        )
        .await
        .expect("failed to create libp2p network");
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
        tracing::info!("Starting Sailfish");
        self.run_tasks().await;
    }
}
