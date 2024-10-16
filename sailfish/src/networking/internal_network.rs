use async_broadcast::{Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::{consensus::Consensus, types::message::SailfishEvent, utils::network::broadcast_event};

const SHOULD_SHUTDOWN: bool = true;
const SHOULD_NOT_SHUTDOWN: bool = false;

pub struct InternalNetwork {
    /// The ID of the node.
    id: u64,

    /// The internal sender is responsible for sending messages inside of the node.
    #[allow(dead_code)]
    internal_sender: Sender<SailfishEvent>,

    /// The external sender is responsible for sending messages outside of the node.
    external_sender: Sender<SailfishEvent>,

    /// The core consensus instance
    consensus: Consensus,
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
        consensus: Consensus,
    ) -> Self {
        Self {
            id,
            internal_sender,
            external_sender,
            consensus,
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

        let events = match self.consensus.handle_event(event) {
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
}
