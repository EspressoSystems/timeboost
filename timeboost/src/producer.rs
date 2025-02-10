use timeboost_core::types::block::timeboost::TimeboostBlock;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::warn;

// TODO: Create a config for where to send blocks to.
pub struct Producer {
    p_rx: Receiver<TimeboostBlock>,
}

impl Producer {
    // TODO: Configurable channel size.
    // TODO: Configurable block recipient.
    pub fn new() -> (Self, Sender<TimeboostBlock>) {
        let (p_tx, p_rx) = channel(100);
        (Self { p_rx }, p_tx)
    }

    pub async fn run(mut self) {
        loop {
            let Some(_block) = self.p_rx.recv().await else {
                warn!("producer receiver disconnected");
                return;
            };
        }
    }
}
