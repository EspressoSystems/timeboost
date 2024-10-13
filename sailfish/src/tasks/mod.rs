use crate::types::message::SailfishEvent;
use anyhow::Result;
use async_broadcast::{Receiver, Sender};
use async_trait::async_trait;
use std::{net::Incoming, sync::Arc};
use tokio::task::JoinHandle;

pub mod round;

/// If the `handle_event` method returns `SHOULD_SHUTDOWN`, the task will shut down.
/// This is just an alias to aid readability.
const SHOULD_SHUTDOWN: bool = true;

#[async_trait]
pub trait Task: Send + Sync + 'static {
    fn new(sender: Sender<Arc<SailfishEvent>>, receiver: Receiver<Arc<SailfishEvent>>) -> Self
    where
        Self: Sized;

    /// Handle an event.  If this returns `SHOULD_SHUTDOWN`, the task will shut down.
    async fn handle_event(&mut self, event: Arc<SailfishEvent>) -> Result<bool> {
        Ok(false)
    }

    /// Handle shutdown.
    async fn handle_shutdown(&self) -> Result<()>;

    /// Append a background task to the task's internal state, keyed by the identifier.
    fn append_background_task(&self, identifier: &str, task: JoinHandle<()>) -> Result<()>;

    /// Trivial getter for the name of the task.
    fn name(&self) -> &str;

    /// Trivial getter for the internal event receiver
    fn internal_event_receiver(&self) -> &Receiver<Arc<SailfishEvent>>;

    /// Make a unique identifier for the task with whatever internal state we're referencing.
    fn make_identifier(&self, identifier: &str) -> String {
        format!("{}::{}", self.name(), identifier)
    }
}
