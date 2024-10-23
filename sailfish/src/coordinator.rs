use anyhow::{Context, Result};
use futures::{future::BoxFuture, FutureExt};
use hotshot::traits::NetworkError;
use hotshot_types::data::ViewNumber;
use std::future::pending;
use tracing::warn;

use crate::{consensus::Consensus, net::Network, types::message::SailfishEvent};

pub struct Coordinator {
    /// The ID of the coordinator.
    id: u64,

    /// The network that the coordinator uses to communicate with other nodes.
    network: Box<dyn Network<Err = NetworkError> + Send>,

    /// The consensus protocol instance that the coordinator is running.
    consensus: Consensus,
}

impl Coordinator {
    pub fn new(
        id: u64,
        network: Box<dyn Network<Err = NetworkError> + Send>,
        consensus: Consensus,
    ) -> Self {
        Self {
            id,
            network,
            consensus,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn run(mut self) -> ! {
        let mut timer: BoxFuture<'static, ViewNumber> = pending().boxed();

        loop {
            tokio::select! { biased;
                timeout = &mut timer => match self.consensus.handle_timeout_recv(timeout).await {
                    Ok(events) => {
                        for event in events {
                            self.bcast(event).await;
                        }
                    }
                    Err(e) => {
                        warn!("Error handling timeout: {:?}", e);
                    }
                },
                msg = self.network.receive() => match msg {
                    Ok(msg) => match self.handle_event(msg).await {
                        Ok(events) => {
                            for event in events {
                                self.bcast(event).await;
                            }
                        }
                        Err(e) => {
                            warn!("Error handling message; error = {:?}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Error receiving message; error = {:?}", e);
                    }
                }
            }
        }
    }

    pub async fn handle_event(&mut self, msg: Vec<u8>) -> Result<Vec<SailfishEvent>> {
        let event: SailfishEvent =
            bincode::deserialize(&msg).context("Error deserializing message")?;
        let in_event = event.transform_send_to_recv();

        self.consensus
            .handle_event(in_event)
            .await
            .context("Error handling event")
    }

    pub async fn bcast(&mut self, msg: SailfishEvent) {
        match bincode::serialize(&msg) {
            Ok(bytes) => {
                if let Err(e) = self.network.broadcast(bytes).await {
                    warn!("Error broadcasting message; error = {:?}", e);
                }
            }
            Err(e) => {
                warn!("Error serializing message; error = {:?}", e);
            }
        }
    }
}
