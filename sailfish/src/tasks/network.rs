use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use async_trait::async_trait;
use hotshot_task::task::TaskState;
use std::sync::Arc;

use crate::{message::SailfishMessage, network_utils::broadcast_event};

pub struct NetworkTaskState {
    internal_event_stream_sender: Sender<Arc<SailfishMessage>>,
    internal_event_stream_receiver: Receiver<Arc<SailfishMessage>>,
}

impl NetworkTaskState {
    pub fn new(
        internal_event_stream_sender: Sender<Arc<SailfishMessage>>,
        internal_event_stream_receiver: Receiver<Arc<SailfishMessage>>,
    ) -> Self {
        NetworkTaskState {
            internal_event_stream_sender,
            internal_event_stream_receiver,
        }
    }

    pub async fn handle(&mut self, event: Arc<SailfishMessage>) {
        // Broadcast an event which is sourced from the external event stream to the
        //internal event stream.
        broadcast_event(event, &self.internal_event_stream_sender).await;
    }
}

#[async_trait]
impl TaskState for NetworkTaskState {
    type Event = SailfishMessage;

    async fn handle_event(
        &mut self,
        event: Arc<Self::Event>,
        _sender: &Sender<Arc<Self::Event>>,
        _receiver: &Receiver<Arc<Self::Event>>,
    ) -> Result<()> {
        self.handle(event).await;

        Ok(())
    }

    async fn cancel_subtasks(&mut self) {}
}
