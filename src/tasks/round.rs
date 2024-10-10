use std::{collections::HashMap, sync::Arc};

use hotshot::types::{BLSPrivKey, BLSPubKey};
use tokio::task::JoinHandle;

use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use async_trait::async_trait;
use hotshot_task::task::{TaskEvent, TaskState};

use crate::message::{RoundNumber, SailfishMessage};

pub struct RoundTaskHandle {
    /// Our public key
    public_key: BLSPubKey,

    /// Our private key
    private_key: BLSPrivKey,

    /// The background round task.
    handle: JoinHandle<()>,
}

impl RoundTaskHandle {
    pub fn shutdown(self) {
        self.handle.abort();
    }
}

pub struct RoundTaskState {
    /// The current round number.
    round: RoundNumber,

    /// The background round tasks.
    pub tasks: HashMap<RoundNumber, RoundTaskHandle>,
}

impl RoundTaskState {
    pub fn new(round: RoundNumber) -> Self {
        Self {
            round,
            tasks: HashMap::new(),
        }
    }

    pub async fn handle(&mut self, event: Arc<SailfishMessage>) {
        match event.as_ref() {
            SailfishMessage::Vertex(vertex) => todo!(),
            SailfishMessage::Timeout(timeout) => todo!(),
            SailfishMessage::NoVote(no_vote) => todo!(),
            SailfishMessage::Shutdown => todo!(),
        }
    }
}

#[async_trait]
impl TaskState for RoundTaskState {
    type Event = SailfishMessage;

    async fn handle_event(
        &mut self,
        event: Arc<Self::Event>,
        sender: &Sender<Arc<Self::Event>>,
        receiver: &Receiver<Arc<Self::Event>>,
    ) -> Result<()> {
        self.handle(event).await;

        Ok(())
    }

    async fn cancel_subtasks(&mut self) {
        for handle in self.tasks.drain().map(|(_round, handle)| handle) {
            handle.shutdown();
        }
    }
}
