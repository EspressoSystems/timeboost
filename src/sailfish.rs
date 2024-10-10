use crate::{
    constants::{EXTERNAL_EVENT_CHANNEL_SIZE, INTERNAL_EVENT_CHANNEL_SIZE},
    message::*,
    tasks::network::NetworkTaskState,
};
use async_broadcast::{broadcast, Receiver, Sender};
use hotshot::types::{BLSPrivKey, BLSPubKey};
use hotshot_task::task::{Task, TaskState};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

pub struct Sailfish {
    /// The public key of the sailfish node.
    public_key: BLSPubKey,

    /// The private key of the sailfish node.
    private_key: BLSPrivKey,

    /// The internal event stream of the sailfish node.
    internal_event_stream: (Sender<Arc<SailfishMessage>>, Receiver<Arc<SailfishMessage>>),

    /// The external event stream of the sailfish node.
    external_event_stream: (Sender<Arc<SailfishMessage>>, Receiver<Arc<SailfishMessage>>),

    /// The background tasks for the sailfish node.
    background_tasks: Vec<JoinHandle<Box<dyn TaskState<Event = SailfishMessage>>>>,
}

impl Sailfish {
    pub fn new(public_key: BLSPubKey, private_key: BLSPrivKey) -> Self {
        Sailfish {
            public_key,
            private_key,
            internal_event_stream: broadcast(INTERNAL_EVENT_CHANNEL_SIZE),
            external_event_stream: broadcast(EXTERNAL_EVENT_CHANNEL_SIZE),
            background_tasks: Vec::new(),
        }
    }

    async fn run_tasks(&mut self) {
        info!("Starting background tasks for Sailfish");
        let network_handle = Task::new(
            NetworkTaskState::new(
                self.internal_event_stream.0.clone(),
                self.internal_event_stream.1.clone(),
            ),
            self.internal_event_stream.0.clone(),
            self.internal_event_stream.1.clone(),
        );

        self.background_tasks.push(network_handle.run());
    }

    pub async fn run(&mut self) {
        tracing::info!("Starting Sailfish");
        self.run_tasks().await;
    }
}
