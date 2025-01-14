use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::{stream::FuturesOrdered, StreamExt};
use libp2p_identity::PeerId;
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

type PeerComm = (mpsc::Sender<NetworkMessage>, mpsc::Sender<()>);
/// The network receives established connections and maintains the
/// communication between the transport layer and the application layer.
#[derive(Debug)]
pub struct Network {
    /// Keypair of this node
    keypair: Keypair,
    /// Connections received from the transport layer
    connections: Arc<RwLock<HashMap<PeerId, PeerComm>>>,
    /// Mapping from public keys to peer Id
    nodes: HashMap<PublicKey, (PeerId, String)>,
    /// Channel for consuming messages from the network
    network_receiver: mpsc::Receiver<NetworkMessage>,
    /// Channel for sending messages from this node
    network_sender: mpsc::Sender<NetworkMessage>,
    /// Shutdown channel
    network_shutdown_sender: mpsc::Sender<()>,
}

impl Network {
    pub async fn start(
        local_id: PeerId,
        local_addr: String,
        keypair: Keypair,
        to_connect: HashMap<PublicKey, (PeerId, String)>,
        ready_sender: mpsc::Sender<()>,
    ) -> Self {
        let transport = Transport::run(local_id, local_addr, to_connect.clone(), &keypair).await;
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let (network_sender, network_receiver) = mpsc::channel(10000);
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
        let (network_shutdown_sender, network_shutdown_receiver) = mpsc::channel(1);
        spawn(Self::run(
            local_id,
            transport,
            Arc::clone(&connections),
            remote_nodes,
            network_sender.clone(),
            ready_sender,
            network_shutdown_receiver,
        ));
        Self {
            keypair,
            connections,
            nodes: to_connect,
            network_receiver,
            network_sender,
            network_shutdown_sender,
        }
    }

    /// Make sure that connections are made by the transport and
    /// set the network as ready when all connections are established
    #[instrument(level = "trace", skip_all, fields(id = %local_id))]
    pub async fn run(
        local_id: PeerId,
        mut transport: Transport,
        connections: Arc<RwLock<HashMap<PeerId, PeerComm>>>,
        to_connect: HashSet<PeerId>,
        network_sender: Sender<NetworkMessage>,
        ready_sender: mpsc::Sender<()>,
        mut network_shutdown_receiver: mpsc::Receiver<()>,
    ) {
        let connection_receiver = transport.rx_connection();
        let mut handles: FuturesOrdered<JoinHandle<Option<()>>> = FuturesOrdered::new();
        loop {
            tokio::select! {
                Some(connection) = connection_receiver.recv() => {
                    let remote_id = connection.remote_id;
                    trace!("received connection from: {}", remote_id);
                    let sender = connection.tx.clone();
                    // Channel for sending outbound communication on the connection
                    let (outbound_sender, outbound_receiver) = mpsc::channel(10000);
                    let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
                    connections
                        .write()
                        .await
                        .insert(connection.remote_id, (outbound_sender, shutdown_sender));
                    let task = spawn(Self::connection_task(
                        connection,
                        sender.clone(),
                        network_sender.clone(),
                        outbound_receiver,
                        shutdown_receiver,
                    ));

                    handles.push_back(task);
                    // Network is considered ready when we have
                    // established connections to 2/3 of the remote nodes
                    if handles.len() == 2 * (to_connect.len() / 3) {
                        let _ = ready_sender.send(()).await;
                    }
                },
                Some(_) = handles.next() => {}
                _ = network_shutdown_receiver.recv() => {
                    trace!("received shutdown signal");
                    break;
                }
            }
        }
    }

    pub async fn connection_task(
        mut connection: Connection,
        sender: Sender<NetworkMessage>,
        network_tx: Sender<NetworkMessage>,
        mut outbound_receiver: mpsc::Receiver<NetworkMessage>,
        mut shutdown_receiver: mpsc::Receiver<()>,
    ) -> Option<()> {
        loop {
            tokio::select! {
                inbound_msg = connection.rx.recv() => {
                    match inbound_msg {
                        Some(msg) => {
                            if let Err(e) = network_tx.send(msg).await {
                                warn!("failed to send inbound message: {:?}", e);
                            }
                        }
                        None => {
                            warn!("inbound channel was closed");
                            break;
                        }
                    }
                }
                outbound_msg = outbound_receiver.recv() => {
                    match outbound_msg {
                        Some(msg) => {
                            if let Err(e) = sender.send(msg).await {
                                warn!("failed to send outbound message: {:?}", e);
                            }
                        }
                        None => {
                            warn!("outbound channel was closed");
                            break;
                        }
                    }
                }
                _ = shutdown_receiver.recv() => {
                    trace!("shutting down connection to peer: {}", connection.remote_id);
                    break;
                }
            }
        }
        None
    }

    pub async fn shut_down(&self) -> Result<(), NetworkError> {
        trace!("shutting down connections to remote nodes");
        for (_, (_, shutdown_sender)) in self.connections.read().await.iter() {
            let _ = shutdown_sender.send(()).await;
        }
        trace!("shutting down network");
        self.network_shutdown_sender.send(()).await.map_err(|_| {
            NetworkError::ChannelSendError("error sending shutdown signal".to_string())
        })?;
        trace!("dropping network state");
        self.connections.write().await.clear();
        Ok(())
    }

    pub async fn broadcast_message(&self, message: Vec<u8>) -> Result<(), NetworkError> {
        let msg: NetworkMessage = NetworkMessage::from(message);
        for (network_sender, _) in self.connections.read().await.values() {
            if (network_sender.send(msg.clone()).await).is_err() {
                return Err(NetworkError::ChannelSendError(
                    "error sending message".to_string(),
                ));
            }
        }
        self.network_sender.send(msg).await.map_err(|_| {
            NetworkError::ChannelSendError("error sending message to self".to_string())
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
            self.network_sender.send(msg.clone()).await.map_err(|_| {
                NetworkError::ChannelSendError("error sending message to self".to_string())
            })?;
        }
        if let Some((peer_id, _)) = self.nodes.get(&recipient) {
            if let Some(connection) = self.connections.read().await.get(peer_id) {
                connection.0.send(msg).await.map_err(|_| {
                    NetworkError::ChannelSendError("error sending message".to_string())
                })?;
                return Ok(());
            }
            return Err(NetworkError::MessageSendError(
                "connection not found".to_string(),
            ));
        }
        Err(NetworkError::LookupError(
            "unable to find the pid connected to the public key".to_string(),
        ))
    }

    pub async fn recv_message(&mut self) -> Result<Vec<u8>, NetworkError> {
        match self.network_receiver.recv().await {
            Some(message) => Ok(message.into_bytes()),
            None => Err(NetworkError::ChannelReceiveError(
                "error receiving message".to_string(),
            )),
        }
    }
}
