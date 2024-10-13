use async_broadcast::{Receiver, Sender};
use async_lock::RwLock;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::{tasks::Task, types::message::SailfishEvent};

pub struct InternalNetwork {
    id: u64,
    #[allow(dead_code)]
    sender: Sender<Arc<SailfishEvent>>,
    tasks: Vec<Arc<RwLock<Box<dyn Task>>>>,
}

impl InternalNetwork {
    pub fn new(id: u64, sender: Sender<Arc<SailfishEvent>>) -> Self {
        Self {
            id,
            sender,
            tasks: Vec::new(),
        }
    }

    pub fn spawn_network_task(
        mut self,
        mut receiver: Receiver<Arc<SailfishEvent>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                self.handle_message(receiver.recv().await).await;
            }
        })
    }

    async fn handle_message(
        &mut self,
        msg: Result<Arc<SailfishEvent>, async_broadcast::RecvError>,
    ) {
        let event = match msg {
            Ok(event) => event,
            Err(e) => {
                warn!("failed to receive event; error = {e:#}");
                return;
            }
        };
        debug!(
            "Node {} received event from internal event stream: {}",
            self.id, event
        );
        for task in &mut self.tasks {
            let mut task = task.write().await;
            match task.handle_event(event.clone()).await {
                Ok(should_shutdown) => {
                    if should_shutdown {
                        info!("Task {} returned shutdown, shutting down", task.name());
                        return;
                    }
                }
                Err(e) => {
                    warn!("Task {} returned error; error = {e:#}", task.name());
                }
            }
        }
    }
}
