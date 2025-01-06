use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::{stream::FuturesOrdered, StreamExt};
use libp2p::PeerId;
use multisig::{Keypair, PublicKey};
use timeboost_crypto::traits::signature_key::SignatureKey;
use timeboost_utils::PeerConfig;
use tokio::{
    spawn,
    sync::{
        mpsc::{self, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use tracing::{instrument, trace, warn};
use transport::{Connection, NetworkMessage, Transport};

use crate::NetworkError;

pub mod transport;

/// The initializer for the network.
pub struct NetworkInitializer<K: SignatureKey + 'static> {
    /// The local peer id
    pub local_id: PeerId,

    /// The bootstrap nodes to connect to.
    pub bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,

    /// The staked nodes to connect to.
    pub staked_nodes: Vec<PeerConfig<K>>,

    /// The keypair
    pub keypair: Keypair,

    /// The local address
    pub bind_address: String,
}

impl<K: SignatureKey + 'static> NetworkInitializer<K> {
    pub fn new(
        local_id: PeerId,
        keypair: Keypair,
        staked_nodes: Vec<PeerConfig<K>>,
        bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,
        bind_address: String,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            local_id,
            bootstrap_nodes,
            staked_nodes,
            keypair,
            bind_address,
        })
    }

    pub async fn into_network(self, tx_ready: mpsc::Sender<()>) -> anyhow::Result<Network> {
        let net_fut = Network::start(
            self.local_id,
            self.bind_address,
            self.keypair,
            self.bootstrap_nodes,
            tx_ready,
        );
        Ok(net_fut.await)
    }
}

/// The network receives established connections and maintains the
/// communication between the transport layer and the application layer.
#[derive(Debug)]
pub struct Network {
    /// Keypair of this node
    keypair: Keypair,
    /// Connections received from the transport layer
    connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
    /// Mapping from public keys to peer Id
    nodes: HashMap<PublicKey, (PeerId, String)>,
    /// Channel for consuming messages from the network
    network_rx: mpsc::Receiver<NetworkMessage>,
    /// Channel for sending messages from this node
    network_tx: mpsc::Sender<NetworkMessage>,
}

impl Network {
    pub async fn start(
        local_id: PeerId,
        local_addr: String,
        keypair: Keypair,
        to_connect: HashMap<PublicKey, (PeerId, String)>,
        tx_ready: mpsc::Sender<()>,
    ) -> Self {
        let transport = Transport::run(
            local_id,
            local_addr,
            to_connect.clone().into_values().collect(),
        )
        .await;
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let (inbound_sender, inbound_receiver) = mpsc::channel(10000);
        let remote_nodes: HashSet<_> = to_connect
            .iter()
            .filter_map(|(_, node)| {
                if node.0 != local_id {
                    Some(node.0)
                } else {
                    None
                }
            })
            .collect();
        spawn(Self::run(
            local_id,
            transport,
            Arc::clone(&connections),
            remote_nodes,
            inbound_sender.clone(),
            tx_ready,
        ));
        Self {
            keypair,
            connections,
            nodes: to_connect,
            network_rx: inbound_receiver,
            network_tx: inbound_sender,
        }
    }

    /// Make sure that connections are made by the transport and
    /// set the network as ready when all connections are established
    #[instrument(level = "trace", skip_all, fields(id = %local_id))]
    pub async fn run(
        local_id: PeerId,
        mut transport: Transport,
        connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
        to_connect: HashSet<PeerId>,
        network_tx: Sender<NetworkMessage>,
        tx_ready: mpsc::Sender<()>,
    ) {
        let connection_receiver = transport.rx_connection();
        let mut handles: FuturesOrdered<JoinHandle<Option<()>>> = FuturesOrdered::new();
        loop {
            tokio::select! {
                Some(connection) = connection_receiver.recv() => {
                    let remote_id = connection.remote_id;
                    trace!("Received connection from: {}", remote_id);
                    let sender = connection.tx.clone();
                    // Channel for sending outbound communication on the connection
                    let (outbound_sender, outbound_receiver) = mpsc::channel(10000);
                    connections
                        .write()
                        .await
                        .insert(connection.remote_id, outbound_sender);
                    let task = spawn(Self::connection_task(
                        connection,
                        sender.clone(),
                        network_tx.clone(),
                        outbound_receiver,
                    ));

                    handles.push_back(task);
                    // We declare the network "ready" when are conneceted to 2/3
                    // of the bootstrap nodes (including ourselves).
                    if handles.len() == 2 * (to_connect.len() / 3) {
                        let _ = tx_ready.send(()).await;
                    }
                },
                Some(_) = handles.next() => {}
            }
        }
    }

    pub async fn connection_task(
        mut connection: Connection,
        sender: Sender<NetworkMessage>,
        network_tx: Sender<NetworkMessage>,
        mut outbound_receiver: mpsc::Receiver<NetworkMessage>,
    ) -> Option<()> {
        loop {
            tokio::select! {
                inbound_msg = connection.rx.recv() => {
                    match inbound_msg {
                        Some(msg) => {
                            if let Err(e) = network_tx.send(msg).await {
                                warn!("Failed to send inbound message: {:?}", e);
                            }
                        }
                        None => {
                            warn!("Inbound channel was closed");
                            break;
                        }
                    }
                }
                outbound_msg = outbound_receiver.recv() => {
                    match outbound_msg {
                        Some(msg) => {
                            if let Err(e) = sender.send(msg).await {
                                warn!("Failed to send outbound message: {:?}", e);
                            }
                        }
                        None => {
                            warn!("Outbound channel was closed");
                            break;
                        }
                    }
                }
            }
        }
        None
    }

    // TODO: Shutdown gracefully
    pub async fn shut_down(&self) -> Result<(), NetworkError> {
        self.connections.write().await.clear();
        Ok(())
    }

    pub async fn broadcast_message(&self, message: Vec<u8>) -> Result<(), NetworkError> {
        let msg: NetworkMessage = NetworkMessage::from(message);
        for connection in self.connections.read().await.values() {
            if (connection.send(msg.clone()).await).is_err() {
                return Err(NetworkError::ChannelSendError(
                    "Error sending message".to_string(),
                ));
            }
        }
        self.network_tx.send(msg).await.map_err(|_| {
            NetworkError::ChannelSendError("Error sending message to self".to_string())
        })?;
        Ok(())
    }

    pub async fn direct_message(
        &self,
        recipient: PublicKey,
        message: Vec<u8>,
    ) -> Result<(), NetworkError> {
        let msg = NetworkMessage::from(message);
        if recipient == self.keypair.public_key() {
            self.network_tx.send(msg.clone()).await.map_err(|_| {
                NetworkError::ChannelSendError("Error sending message to self".to_string())
            })?;
        }
        if let Some((peer_id, _)) = self.nodes.get(&recipient) {
            if let Some(connection) = self.connections.read().await.get(peer_id) {
                connection.send(msg).await.map_err(|_| {
                    NetworkError::ChannelSendError("Error sending message".to_string())
                })?;
                return Ok(());
            }
            return Err(NetworkError::MessageSendError(
                "Connection not found".to_string(),
            ));
        }
        Err(NetworkError::LookupError(
            "Unable to find the pid connected to the public key".to_string(),
        ))
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
