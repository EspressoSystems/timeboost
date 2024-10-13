use std::{collections::HashMap, sync::Arc};

use hotshot::types::{BLSPrivKey, BLSPubKey};
use tokio::task::JoinHandle;

use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use async_trait::async_trait;
use hotshot_task::task::TaskState;
use hotshot_types::data::ViewNumber;

use crate::types::message::SailfishEvent;

pub struct RoundTaskHandle {
    /// Our public key
    #[allow(dead_code)]
    public_key: BLSPubKey,

    /// Our private key
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    round: ViewNumber,

    /// The background round tasks.
    pub tasks: HashMap<ViewNumber, RoundTaskHandle>,
}

impl RoundTaskState {
    pub fn new(round: ViewNumber) -> Self {
        Self {
            round,
            tasks: HashMap::new(),
        }
    }

    pub async fn handle(&mut self, event: Arc<SailfishEvent>) {
        match event.as_ref() {
            SailfishEvent::Vertex(vertex) => tracing::debug!("{}", vertex),
            SailfishEvent::Timeout(timeout) => tracing::debug!("{}", timeout),
            SailfishEvent::NoVote(no_vote) => tracing::debug!("{}", no_vote),
            SailfishEvent::Shutdown => tracing::debug!("{}", "Shutdown"),
            SailfishEvent::DummySend(dummy) => tracing::debug!("DummySend({})", dummy),
            SailfishEvent::DummyRecv(dummy) => tracing::debug!("DummyRecv({})", dummy),
        }
    }
}

#[async_trait]
impl TaskState for RoundTaskState {
    type Event = SailfishEvent;

    async fn handle_event(
        &mut self,
        event: Arc<Self::Event>,
        _sender: &Sender<Arc<Self::Event>>,
        _receiver: &Receiver<Arc<Self::Event>>,
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
