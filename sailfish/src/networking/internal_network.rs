use async_broadcast::{Receiver, Sender};
use async_lock::RwLock;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::{tasks::Task, types::message::SailfishEvent, utils::network::broadcast_event};

pub struct InternalNetwork {
    /// The ID of the node.
    id: u64,

    /// The internal sender is responsible for sending messages inside of the node.
    #[allow(dead_code)]
    internal_sender: Sender<SailfishEvent>,

    /// The external sender is responsible for sending messages outside of the node.
    external_sender: Sender<SailfishEvent>,

    /// The tasks that the node is responsible for.
    tasks: Vec<Arc<RwLock<Box<dyn Task>>>>,
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
    ) -> Self {
        Self {
            id,
            internal_sender,
            external_sender,
            tasks: Vec::new(),
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
                        self.handle_message(event, self.external_sender.clone())
                            .await
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
    /// * `external_sender` - The sender for messages to be sent outside the node.
    async fn handle_message(
        &mut self,
        event: SailfishEvent,
        external_sender: Sender<SailfishEvent>,
    ) {
        debug!(
            "Node {} received event from internal event stream: {}",
            self.id, event
        );

        // TODO: This is a potential bottleneck as a single lagging task
        // can cause all events to be delayed. This will be alleviated when
        // we move to a model where each node runs in a background task.
        for task in &mut self.tasks {
            let mut task = task.write().await;
            match task.handle_event(event.clone()).await {
                Ok(events) => {
                    // TODO: This is a bottleneck since broadcast_event, while quick, can
                    // add up in a serial operation. This will be addresed later.
                    for event in events {
                        broadcast_event(event, &external_sender).await;
                    }
                }
                Err(e) => {
                    warn!("Task {} returned error; error = {e:#}", task.name());
                }
            }
        }
    }

    pub fn register_task(&mut self, task: Arc<RwLock<Box<dyn Task>>>) {
        self.tasks.push(task);
    }
}
