use crate::{types::message::SailfishEvent, utils::network::broadcast_event};
use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use hotshot::{traits::implementations::Libp2pNetwork, types::BLSPubKey};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};

/// Represents the external network interface for Sailfish nodes.
/// This struct manages communication between the local node and the wider network.
pub struct ExternalNetwork {
    /// Unique identifier for this node.
    id: u64,
    /// The underlying libp2p network implementation.
    network: Libp2pNetwork<BLSPubKey>,
    /// Sender for events that need to be processed internally by the node.
    internal_event_sender: Sender<SailfishEvent>,

    /// Receiver for internal events. Currently unused.
    #[allow(dead_code)]
    internal_event_receiver: Receiver<SailfishEvent>,

    /// Sender for events that need to be broadcast to the external network. Currently unused.
    #[allow(dead_code)]
    external_event_sender: Sender<SailfishEvent>,
    /// Receiver for events that need to be broadcast to the external network.
    external_event_receiver: Receiver<SailfishEvent>,
}

impl ExternalNetwork {
    pub fn new(
        network: Libp2pNetwork<BLSPubKey>,
        id: u64,
        internal_event_sender: Sender<SailfishEvent>,
        internal_event_receiver: Receiver<SailfishEvent>,
        external_event_sender: Sender<SailfishEvent>,
        external_event_receiver: Receiver<SailfishEvent>,
    ) -> Self {
        Self {
            id,
            network,
            internal_event_sender,
            internal_event_receiver,
            external_event_sender,
            external_event_receiver,
        }
    }

    #[instrument(
        skip_all,
        target = "initialize",
        fields(id = self.id)
    )]
    pub async fn initialize(&self) -> Result<()> {
        info!("Waiting for network to be ready");
        self.network.wait_for_ready().await;
        Ok(())
    }

    #[instrument(
        skip_all,
        target = "network",
        fields(id = self.id)
    )]
    pub fn spawn_network_task(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = self.network.recv_message() => {
                        let message = match msg {
                            Ok(msg) => msg,
                            Err(e) => {
                                warn!("Failed to deserialize network message; error = {e:#}");
                                continue;
                            }
                        };
                        self.handle_incoming_message(message).await;
                    }
                    msg = self.external_event_receiver.recv() => {
                        // First, verify that the message is validly received.
                        let msg = match msg {
                            Ok(msg) => msg,
                            Err(e) => {
                                warn!("Failed to receive event; error = {e:#}");
                                continue;
                            }
                        };

                        // Then, serialize the message.
                        let serialized_msg = match bincode::serialize(&msg) {
                            Ok(serialized_msg) => serialized_msg,
                            Err(e) => {
                                warn!("Failed to serialize SailfishEvent; error = {e:#}");
                                continue;
                            }
                        };

                        // TODO: Verify that the message is supposed to be sent to the network.
                        // this can be accomplished by some type of specification on the SailfishEvent.

                        // Finally, broadcast the message to the other nodes in the network.
                        self.network.broadcast_message(serialized_msg, Topic::Global, BroadcastDelay::None).await.unwrap();
                    }
                }
            }
        })
    }

    #[instrument(
        skip_all,
        target = "network",
        fields(id = self.id)
    )]
    async fn handle_incoming_message(&self, message: Vec<u8>) {
        let event: SailfishEvent = match bincode::deserialize(&message) {
            Ok(event) => event,
            Err(e) => {
                warn!("Failed to deserialize SailfishEvent; error = {e:#}");
                return;
            }
        };

        debug!("Node {} received message from network: {}", self.id, event);

        match event {
            SailfishEvent::Shutdown => {
                info!("Received shutdown event, shutting down");
                // TODO: Propagate shutdown signal.
            }
            SailfishEvent::VertexCertificateSend(certificate) => {
                broadcast_event(
                    SailfishEvent::VertexCertificateRecv(certificate),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::VertexSend(vertex, signature) => {
                broadcast_event(
                    SailfishEvent::VertexRecv(vertex, signature),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::TimeoutSend(round) => {
                broadcast_event(
                    SailfishEvent::TimeoutRecv(round),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::NoVoteSend(round) => {
                broadcast_event(
                    SailfishEvent::NoVoteRecv(round),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::TimeoutVoteSend(vote) => {
                broadcast_event(
                    SailfishEvent::TimeoutVoteRecv(vote),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::NoVoteVoteSend(vote) => {
                broadcast_event(
                    SailfishEvent::NoVoteVoteRecv(vote),
                    &self.internal_event_sender,
                )
                .await;
            }
            SailfishEvent::VertexVoteSend(vote) => {
                broadcast_event(
                    SailfishEvent::VertexVoteRecv(vote),
                    &self.internal_event_sender,
                )
                .await;
            }
            _ => {
                warn!("Received unprocessable event from network: {}", event);
            }
        }
    }
}
