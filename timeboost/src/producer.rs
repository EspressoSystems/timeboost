use anyhow::{bail, Result};

use timeboost_core::types::block::Block;
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    watch,
};

// TODO: Create a config for where to send blocks to.
pub struct Producer {
    p_rx: Receiver<Block>,
    shutdown_rx: watch::Receiver<()>,
}

impl Producer {
    // TODO: Configurable channel size.
    // TODO: Configurable block recipient.
    pub fn new(shutdown_rx: watch::Receiver<()>) -> (Self, Sender<Block>) {
        let (p_tx, p_rx) = channel(100);
        (Self { p_rx, shutdown_rx }, p_tx)
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                block = self.p_rx.recv() => {
                    let Some(_block) = block else {
                        bail!("producer receiver disconnected");
                    };

                    // TODO: Send block to the network.
                }
                _ = self.shutdown_rx.changed() => {
                    return Ok(());
                }
            }
        }
    }
}
