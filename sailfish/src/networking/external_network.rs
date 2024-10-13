use crate::{types::message::SailfishEvent, utils::network::broadcast_event};
use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use hotshot::{
    traits::{implementations::Libp2pNetwork, NetworkError},
    types::BLSPubKey,
};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

pub struct ExternalNetwork {
    id: u64,
    network: Libp2pNetwork<BLSPubKey>,
    internal_event_sender: Sender<Arc<SailfishEvent>>,
    internal_event_receiver: Receiver<Arc<SailfishEvent>>,
}

impl ExternalNetwork {
    pub fn new(
        network: Libp2pNetwork<BLSPubKey>,
        id: u64,
        internal_event_sender: Sender<Arc<SailfishEvent>>,
        internal_event_receiver: Receiver<Arc<SailfishEvent>>,
    ) -> Self {
        Self {
            id,
            network,
            internal_event_sender,
            internal_event_receiver,
        }
    }

    pub async fn initialize(&self) -> Result<()> {
        info!("Waiting for network to be ready");
        self.network.wait_for_ready().await;

        debug!(
            "Sending dummy event to network {}",
            SailfishEvent::DummySend(self.id)
        );

        // Kickstart the network with a dummy send event
        self.network
            .broadcast_message(
                bincode::serialize(&SailfishEvent::DummySend(self.id))?,
                Topic::Global,
                BroadcastDelay::None,
            )
            .await?;

        Ok(())
    }

    pub fn spawn_network_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let msg = self.network.recv_message().await;
                self.handle_incoming_message(msg).await;
            }
        })
    }

    async fn handle_incoming_message(&self, msg: Result<Vec<u8>, NetworkError>) {
        let message = match msg {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to deserialize network message; error = {e:#}");
                return;
            }
        };

        let event: SailfishEvent = match bincode::deserialize(&message) {
            Ok(event) => event,
            Err(e) => {
                warn!("Failed to deserialize SailfishEvent; error = {e:#}");
                return;
            }
        };

        debug!("Node {} received message from network: {}", self.id, event);

        if event == SailfishEvent::Shutdown {
            info!("Received shutdown event, shutting down");
            return;
        }

        match event {
            SailfishEvent::DummySend(sender_id) => {
                broadcast_event(
                    Arc::new(SailfishEvent::DummyRecv(sender_id)),
                    &self.internal_event_sender,
                )
                .await;
            }
            _ => {}
        }
    }
}
