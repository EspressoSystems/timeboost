use std::time::Duration;

use async_broadcast::{Receiver, Sender};
use hotshot::types::BLSPubKey;
use hotshot_types::data::ViewNumber;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::{
    consensus::{verify_committed_round, Consensus},
    types::{certificate::make_genesis_vertex_certificate, message::SailfishEvent},
    utils::network::broadcast_event,
};

const SHOULD_SHUTDOWN: bool = true;
const SHOULD_NOT_SHUTDOWN: bool = false;

pub struct InternalNetwork {
    /// The ID of the node.
    id: u64,

    /// The public key of the node.
    public_key: BLSPubKey,

    /// The internal sender is responsible for sending messages inside of the node.
    #[allow(dead_code)]
    internal_sender: Sender<SailfishEvent>,

    /// The external sender is responsible for sending messages outside of the node.
    external_sender: Sender<SailfishEvent>,

    /// The core consensus instance
    consensus: Consensus,

    /// The timeout handle for the network
    timeout_handle: JoinHandle<()>,
}

impl InternalNetwork {
    /// Creates a new `InternalNetwork` instance.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the node.
    /// * `internal_sender` - The sender for internal messages within the node.
    /// * `external_sender` - The sender for messages to be sent outside the node.
    ///
    /// # Returns
    ///
    /// A new `InternalNetwork` instance.
    pub fn new(
        id: u64,
        internal_sender: Sender<SailfishEvent>,
        external_sender: Sender<SailfishEvent>,
        public_key: BLSPubKey,
        consensus: Consensus,
    ) -> Self {
        let round = consensus.round() + 1;

        Self {
            id,
            internal_sender: internal_sender.clone(),
            external_sender,
            public_key,
            consensus,
            timeout_handle: Self::spawn_timeout_task(round, internal_sender),
        }
    }

    /// Spawns a network task to handle incoming events.
    ///
    /// This method creates an asynchronous task that continuously listens for events
    /// and processes them using the `handle_message` method.
    ///
    /// # Arguments
    ///
    /// * `receiver` - The receiver for incoming `SailfishEvent`s.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned task.
    pub fn spawn_network_task(mut self, mut receiver: Receiver<SailfishEvent>) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Create a genesis vertex certificate.
            let certificate = make_genesis_vertex_certificate(self.public_key);

            // Broadcast the genesis certificate to the network. This will kickstart the network.
            // All nodes will aggregate these certificates and use them as their basis.
            broadcast_event(
                SailfishEvent::VertexCertificateSend(certificate),
                &self.external_sender,
            )
            .await;

            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        if self.handle_message(event).await {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to receive event; error = {e:#}");
                    }
                }
            }
        })
    }

    /// Handles an incoming message by processing it through all registered tasks.
    ///
    /// This method iterates through all tasks and calls their `handle_event` method
    /// with the received event. It also handles task shutdown requests and errors.
    /// When a task returns new events, they are broadcast to all other nodes.
    ///
    /// # Arguments
    ///
    /// * `event` - The `SailfishEvent` to be processed.
    async fn handle_message(&mut self, event: SailfishEvent) -> bool {
        debug!(
            "Node {} received event from internal event stream: {}",
            self.id, event
        );

        if let SailfishEvent::Shutdown = event {
            return SHOULD_SHUTDOWN;
        }

        // If we've committed a new round, we need to spawn a new timeout task. But we'll
        // still forward the event to the Consensus state so it can update its states.
        if let SailfishEvent::VertexCommitted(round, signature) = &event {
            // TODO: This isn't an excellent design pulling lower state into the internal network
            // but it's convenient for now because otherwise the Consensus state would need to be
            // aware of the external network since we need to short-circuit and send the timeout
            // event to the external network as *soon* as a timeout happens.
            if let Err(e) =
                verify_committed_round(*round, signature, &self.consensus.quorum_membership)
            {
                warn!("Failed to verify committed round; error = {e:#}");
            } else {
                // TODO: This assumes that the round that we're committing is the round that the timeout is
                // targeting. We need to add a check to make sure that this is the case. (self.round + 1 == round)

                // Cancel the previous timeout handle.
                self.timeout_handle.abort();

                let round_number = *round + 1;

                // Spawn a new timeout handle for the next round and hand it a reference to the internal sender
                // so it can broadcast the timeout event to back to the Consensus module.
                self.timeout_handle =
                    Self::spawn_timeout_task(round_number, self.internal_sender.clone());
            }
        }

        let events = match self.consensus.handle_event(event).await {
            Ok(events) => events,
            Err(e) => {
                warn!("Consensus returned error; error = {e:#}");
                return SHOULD_NOT_SHUTDOWN;
            }
        };

        for event in events {
            broadcast_event(event, &self.external_sender).await;
        }

        SHOULD_NOT_SHUTDOWN
    }

    /// Spawns a timeout task to handle timeouts.
    ///
    /// This method creates an asynchronous task that continuously listens for timeouts
    /// and processes them using the `handle_timeout` method.
    pub fn spawn_timeout_task(
        round_number: ViewNumber,
        internal_sender: Sender<SailfishEvent>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // We are timing out on the next round always. This round is influenced by whatever round we're in.
            // We *distinctly* do not use the last comitted round because it's possible that we never committed
            // a round, due to a prior timeout (consecutive bad leaders).
            tokio::time::sleep(Duration::from_secs(4)).await;
            let event = SailfishEvent::TimeoutSend(round_number);
            broadcast_event(event, &internal_sender).await;
        })
    }
}
