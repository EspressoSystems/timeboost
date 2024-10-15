use crate::types::message::SailfishEvent;
use anyhow::Result;
use async_broadcast::Sender;
use async_trait::async_trait;

pub mod round;

#[async_trait]
pub trait Task: Send + Sync + 'static {
    fn new(external_sender: Sender<SailfishEvent>) -> Self
    where
        Self: Sized;

    /// Handle a [`SailfishEvent`] and return any new events to be broadcast in the event loop.
    async fn handle_event(&mut self, event: SailfishEvent) -> Result<Vec<SailfishEvent>>;

    /// Trivial getter for the name of the task.
    fn name(&self) -> &str;

    /// Make a unique identifier for the task with whatever internal state we're referencing.
    fn make_identifier(&self, identifier: &str) -> String {
        format!("{}::{}", self.name(), identifier)
    }
}
