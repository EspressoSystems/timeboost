use crate::types::message::SailfishEvent;
use anyhow::Result;
use async_broadcast::Sender;
use async_trait::async_trait;
use std::sync::Arc;

pub mod round;

#[async_trait]
pub trait Task: Send + Sync + 'static {
    fn new(external_sender: Sender<Arc<SailfishEvent>>) -> Self
    where
        Self: Sized;

    /// Handle an event.  If this returns `SHOULD_SHUTDOWN`, the task will shut down.
    async fn handle_event(
        &mut self,
        _event: Arc<SailfishEvent>,
        _external_sender: Sender<Arc<SailfishEvent>>,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Trivial getter for the name of the task.
    fn name(&self) -> &str;

    /// Make a unique identifier for the task with whatever internal state we're referencing.
    fn make_identifier(&self, identifier: &str) -> String {
        format!("{}::{}", self.name(), identifier)
    }
}
