use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{atomic::AtomicBool, Arc},
};

use futures::future::join_all;
use libp2p::PeerId;
use libp2p_identity::Keypair;
use timeboost_crypto::{sg_encryption::Committee, traits::signature_key::SignatureKey};
use timeboost_utils::PeerConfig;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{self, Sender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use transport::{Connection, NetworkMessage, Transport};

use crate::{
    network::{client::derive_libp2p_keypair, NetworkNodeConfig, NetworkNodeConfigBuilder},
    NetworkError,
};

pub mod transport;

/// The initializer for the basic network.
pub struct NetworkInitializer<K: SignatureKey + 'static> {
    pub local_id: PeerId,
    /// The bootstrap nodes to connect to.
    pub bootstrap_nodes: Vec<(PeerId, String)>,

    /// The staked nodes to connect to.
    pub staked_nodes: Vec<PeerConfig<K>>,

    // /// The network configuration.
    // pub config: NetworkNodeConfig<K>,
    /// The libp2p keypair
    pub keypair: Keypair,

    pub bind_address: String,
}

impl<K: SignatureKey + 'static> NetworkInitializer<K> {
    pub fn new(
        local_id: PeerId,
        private_key: &K::PrivateKey,
        staked_nodes: Vec<PeerConfig<K>>,
        bootstrap_nodes: HashSet<(PeerId, String)>,
        bind_address: String,
    ) -> anyhow::Result<Self> {
        let libp2p_keypair = derive_libp2p_keypair::<K>(private_key).expect("Keypair to derive");

        let bootstrap_nodes = bootstrap_nodes
            .into_iter()
            .collect::<Vec<(PeerId, String)>>();

        Ok(Self {
            local_id,
            bootstrap_nodes,
            staked_nodes,
            keypair: libp2p_keypair,
            bind_address,
        })
    }

    pub async fn into_network(self, tx_ready: oneshot::Sender<()>) -> anyhow::Result<Network> {
        // let mut network_config = NetworkConfig::default();
        // network_config.config.known_nodes_with_stake = self.staked_nodes.to_vec();
        // network_config.libp2p_config = Some(Libp2pConfig {
        //     bootstrap_nodes: self.bootstrap_nodes.clone(),
        // });

        // We don't have any DA nodes in Sailfish.
        // network_config.config.known_da_nodes = vec![];
        // Create the Libp2p network
        Ok(Network::start(
            self.local_id,
            self.bind_address,
            self.bootstrap_nodes,
            tx_ready,
        )
        .await)
    }
}

#[derive(Debug)]
pub struct Network {
    main_task: JoinHandle<()>,
    connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
    network_rx: mpsc::Receiver<NetworkMessage>,
}

impl Network {
    pub async fn start(
        local_id: PeerId,
        local_addr: String,
        to_connect: Vec<(PeerId, String)>,
        tx_ready: oneshot::Sender<()>,
    ) -> Self {
        let transport = Transport::run(local_id, local_addr, to_connect).await;
        let handle = Handle::current();
        let connections = Arc::new(RwLock::new(HashMap::new()));
        // receiving messages each for peer and send to network_rx
        let (network_tx, network_rx) = mpsc::channel(10000);
        let main_task = handle.spawn(Self::run(
            transport,
            Arc::clone(&connections),
            network_tx,
            tx_ready,
        ));
        Self {
            main_task,
            connections,
            network_rx,
        }
    }

    pub async fn run(
        mut transport: Transport,
        connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
        network_tx: Sender<NetworkMessage>,
        tx_ready: oneshot::Sender<()>,
    ) {
        let rx_connection = transport.rx_connection();
        let mut handles: HashMap<PeerId, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        while let Some(connection) = rx_connection.recv().await {
            let remote_id = connection.remote_id;
            // if let Some(task) = connections.remove(&remote_id) {
            //     // wait until previous sync task completes
            //     task.await.ok();
            // }

            let sender = connection.tx.clone();
            // let authority = peer_id as AuthorityIndex;
            // block_fetcher
            //     .register_authority(
            //         authority,
            //         sender,
            //         connection.latency_last_value_receiver.clone(),
            //     )
            //     .await;
            // inner.connected_authorities.lock().insert(authority);
            let (bc_sender, bc_receiver) = mpsc::channel(10000);
            connections
                .write()
                .await
                .insert(connection.remote_id, bc_sender);
            let task = handle.spawn(Self::connection_task(
                connection,
                sender.clone(),
                network_tx.clone(),
                bc_receiver,
            ));
            handles.insert(remote_id, task);
        }
        tx_ready.send(());
        join_all(handles.into_values().into_iter()).await;
        // Arc::try_unwrap(block_fetcher)
        //     .unwrap_or_else(|_| panic!("Failed to drop all connections"))
        //     .shutdown()
        //     .await;
        //network.shutdown().await;
    }

    pub async fn connection_task(
        mut connection: Connection,
        sender: Sender<NetworkMessage>,
        network_tx: Sender<NetworkMessage>,
        mut bc_receiver: mpsc::Receiver<NetworkMessage>,
    ) -> Option<()> {
        loop {
            tokio::select! {
                inbound_msg = connection.rx.recv() => {
                    if let Some(msg) = inbound_msg {
                        sender.send(msg).await.ok();
                    } else {
                        break
                    }
                }
                outbound_msg = bc_receiver.recv() => {
                    if let Some(msg) = outbound_msg {
                        network_tx.send(msg).await.ok();
                    } else {
                        break
                    }
                }
            }
        }
        //        self.connections.remove()
        None
    }

    pub async fn shut_down(&self) -> Result<(), NetworkError> {
        todo!()
    }

    pub async fn broadcast_message(&self, message: Vec<u8>) -> Result<(), NetworkError> {
        for connection in self.connections.read().await.values() {
            if let Err(_) = connection.send(NetworkMessage::from(message.clone())).await {
                return Err(NetworkError::ChannelSendError(
                    "Error sending message".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub async fn direct_message(
        &self,
        recipient: PeerId,
        message: Vec<u8>,
    ) -> Result<(), NetworkError> {
        todo!()
    }

    pub async fn recv_message(&mut self) -> Result<Vec<u8>, NetworkError> {
        match self.network_rx.recv().await {
            Some(message) => Ok(message.into_bytes()),
            None => Err(NetworkError::ChannelReceiveError(
                "Error receiving message".to_string(),
            )),
        }
    }
}
