use async_broadcast::{SendError, Sender};
use tracing::{error, warn};

pub async fn broadcast_event<E: Clone + std::fmt::Debug>(event: E, sender: &Sender<E>) {
    match sender.broadcast_direct(event).await {
        Ok(None) => (),
        Ok(Some(overflowed)) => {
            error!(
                "Event sender queue overflow, Oldest event removed form queue: {:?}",
                overflowed
            );
        }
        Err(SendError(e)) => {
            warn!(
                "Event: {:?} Sending failed, event stream probably shutdown",
                e
            );
        }
    }
}
