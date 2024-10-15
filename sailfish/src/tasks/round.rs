use anyhow::Result;
use std::{collections::HashMap, sync::Arc};

use async_lock::RwLock;
use hotshot::types::{BLSPrivKey, BLSPubKey};

use async_broadcast::Sender;
use async_trait::async_trait;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use tracing::debug;

use crate::{tasks::Task, types::message::SailfishEvent};

pub struct RoundTaskHandle {
    /// Our public key
    #[allow(dead_code)]
    public_key: BLSPubKey,

    /// Our private key
    #[allow(dead_code)]
    private_key: BLSPrivKey,
}

impl RoundTaskHandle {}

pub struct RoundTaskState {
    /// The current round number.
    #[allow(dead_code)]
    round: ViewNumber,

    /// The background round tasks.
    pub tasks: HashMap<ViewNumber, Arc<RwLock<Box<dyn Task>>>>,

    /// The external event sender.
    #[allow(dead_code)]
    external_sender: Sender<SailfishEvent>,
}

impl RoundTaskState {
    pub fn new(round: ViewNumber, external_sender: Sender<SailfishEvent>) -> Self {
        Self {
            round,
            tasks: HashMap::new(),
            external_sender,
        }
    }

    pub async fn handle(&mut self, event: SailfishEvent) {
        debug!("{}", event);
    }
}

#[async_trait]
impl Task for RoundTaskState {
    fn new(external_sender: Sender<SailfishEvent>) -> Self {
        Self {
            round: ViewNumber::genesis(),
            tasks: HashMap::new(),
            external_sender,
        }
    }

    fn name(&self) -> &str {
        "RoundTask"
    }

    fn make_identifier(&self, identifier: &str) -> String {
        format!("{}::{}", self.name(), identifier)
    }

    async fn handle_event(&mut self, _event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
        Ok(vec![])
    }
}
