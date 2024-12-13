use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::future::join_all;
use libp2p::PeerId;
use libp2p_identity::Keypair;
use multisig::PublicKey;
use timeboost_crypto::traits::signature_key::SignatureKey;
use timeboost_utils::PeerConfig;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{self, Sender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use tracing::{instrument, trace, warn};
use transport::{Connection, NetworkMessage, Transport};

use crate::{p2p::client::derive_libp2p_keypair, NetworkError};

pub mod transport;

/// The initializer for the network.
pub struct NetworkInitializer<K: SignatureKey + 'static> {
    /// The local peer id
    pub local_id: PeerId,

    /// The bootstrap nodes to connect to.
    pub bootstrap_nodes: Vec<(PeerId, String)>,

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
        let net_fut = Network::start(
            self.local_id,
            self.bind_address,
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
    /// Handle for the main task
    _main_task: JoinHandle<()>,
    /// Connections received from the transport layer
    connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
    /// Channel for consuming messages from the network
    network_rx: mpsc::Receiver<NetworkMessage>,
}

impl Network {
    pub async fn start(
        local_id: PeerId,
        local_addr: String,
        to_connect: Vec<(PeerId, String)>,
        tx_ready: oneshot::Sender<()>,
    ) -> Self {
        let transport = Transport::run(local_id, local_addr, to_connect.clone()).await;
        let handle = Handle::current();
        let connections = Arc::new(RwLock::new(HashMap::new()));
        let (inbound_sender, inbound_receiver) = mpsc::channel(10000);
        trace!("Running main network task");
        let main_task = handle.spawn(Self::run(
            local_id.clone(),
            transport,
            Arc::clone(&connections),
            to_connect,
            inbound_sender,
            tx_ready,
        ));
        Self {
            _main_task: main_task,
            connections,
            network_rx: inbound_receiver,
        }
    }

    /// Make sure that connections are made by the transport and
    /// set the network as ready when all connections are established
    #[instrument(level = "trace", skip_all, fields(id = %local_id))]
    pub async fn run(
        local_id: PeerId,
        mut transport: Transport,
        connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
        mut to_connect: Vec<(PeerId, String)>,
        network_tx: Sender<NetworkMessage>,
        tx_ready: oneshot::Sender<()>,
    ) {
        let connection_receiver = transport.rx_connection();
        let mut handles: HashMap<PeerId, JoinHandle<Option<()>>> = HashMap::new();
        let handle = Handle::current();
        while let Some(connection) = connection_receiver.recv().await {
            let remote_id = connection.remote_id;
            trace!("Received connection from: {}", remote_id);
            if let Some(task) = handles.remove(&remote_id) {
                // Wait until previous sync task completes
                task.await.ok();
            }
            let sender = connection.tx.clone();
            // Channel for sending outbound communication on the connection
            let (outbound_sender, outbound_receiver) = mpsc::channel(10000);
            connections
                .write()
                .await
                .insert(connection.remote_id, outbound_sender);
            let task = handle.spawn(Self::connection_task(
                connection,
                sender.clone(),
                network_tx.clone(),
                outbound_receiver,
            ));

            handles.insert(remote_id, task);
            to_connect.retain(|(id, _)| id != &remote_id);
            if to_connect.len() == 1 {
                // only our own peer id left
                break;
            }
        }
        let _ = tx_ready.send(());
        join_all(handles.into_values()).await;
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
        for connection in self.connections.read().await.values() {
            if (connection.send(NetworkMessage::from(message.clone())).await).is_err() {
                return Err(NetworkError::ChannelSendError(
                    "Error sending message".to_string(),
                ));
            }
        }
        Ok(())
    }

    // TODO: Implement direct messaging
    pub async fn direct_message(
        &self,
        _recipient: PublicKey,
        message: Vec<u8>,
    ) -> Result<(), NetworkError> {
        self.broadcast_message(message).await
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
