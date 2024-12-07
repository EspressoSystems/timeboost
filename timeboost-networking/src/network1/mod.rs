use std::{collections::HashMap, sync::Arc};

use futures::future::join_all;
use libp2p::PeerId;
use timeboost_crypto::sg_encryption::Committee;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{self, Sender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use transport::{Connection, NetworkMessage, Transport};

use crate::NetworkError;

pub mod transport;

#[derive(Debug)]
pub struct Network {
    main_task: JoinHandle<()>,
    connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
    tx_ready: oneshot::Sender<()>,
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
        let main_task = handle.spawn(Self::run(transport, Arc::clone(&connections), network_tx));
        Self {
            main_task,
            connections,
            tx_ready,
            network_rx,
        }
    }

    pub async fn run(
        mut transport: Transport,
        connections: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
        network_tx: Sender<NetworkMessage>,
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
