use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use hotshot::traits::NetworkError;
use hotshot_types::data::ViewNumber;
use std::future::pending;
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::{
    consensus::Consensus,
    net::Network,
    types::{certificate::VertexCertificate, message::SailfishEvent},
};

pub struct Coordinator {
    id: u64,
    network: Box<dyn Network<Err = NetworkError> + Send>,
    consensus: Consensus,

    shutdown_receiver: mpsc::Receiver<()>,
    shutdown_sender: mpsc::Sender<()>,
}

impl Coordinator {
    pub fn new(i: u64, n: Box<dyn Network<Err = NetworkError> + Send>, c: Consensus) -> Self {
        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        Self {
            id: i,
            network: n,
            consensus: c,
            shutdown_receiver,
            shutdown_sender,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn shutdown_sender(&self) -> mpsc::Sender<()> {
        self.shutdown_sender.clone()
    }

    pub async fn go(mut self) -> ! {
        tracing::info!("Coordinator starting");
        self.network.wait_for_ready().await;
        let mut timer: BoxFuture<'static, ViewNumber> = pending().boxed();
        tracing::info!("Coordinator timer set");

        // Initiate consensus with a genesis certificate
        let genesis_cert = VertexCertificate::genesis(self.consensus.context.public_key);
        tracing::info!("Coordinator genesis cert set");
        // Send out the genesis certificate
        // self.bcast(SailfishEvent::VertexCertificateSend(genesis_cert))
        //     .await;
        tracing::info!("Coordinator genesis cert broadcasted");
        loop {
            tracing::info!("Coordinator loop");
            tokio::select! { biased;
                vnr = &mut timer => match self.consensus.on_timeout(vnr).await {
                    Ok(actions) => {
                        for a in actions {
                            self.on_action(a, &mut timer).await
                        }
                    }
                    Err(err) => {
                        error!(%err, "consensus error on internal timeout")
                    }
                },
                msg = self.network.receive() => match msg {
                    Ok(msg) => match self.on_message(&msg).await {
                        Ok(actions) => {
                        tracing::info!("Coordinator actions received");
                            for a in actions {
                                self.on_action(a, &mut timer).await
                            }
                        }
                        Err(err) => {
                            warn!(%err, "error processing incoming message")
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize network message; error = {e:#}");
                        continue;
                    }
                },
                _ = self.shutdown_receiver.recv() => {
                    tracing::info!("Coordinator shutting down");
                }
            }
        }
    }

    /// Handle external message.
    async fn on_message(&mut self, message: &[u8]) -> Result<Vec<SailfishEvent>> {
        let message = bincode::deserialize(message)?;
        self.consensus.on_message(message).await
    }

    /// Handle an internal action being sent to the network.
    async fn on_action(
        &mut self,
        action: SailfishEvent,
        timer: &mut BoxFuture<'static, ViewNumber>,
    ) {
        let out_action = action.transform_recv_to_send();
        match out_action {
            SailfishEvent::Shutdown => todo!(),
            SailfishEvent::VertexCommitted(round_number, _) => {
                *timer = tokio::time::sleep(std::time::Duration::from_secs(4))
                    .map(move |_| round_number)
                    .boxed()
            }
            _ => self.bcast(out_action).await,
        }
    }

    async fn bcast(&mut self, msg: SailfishEvent) {
        match bincode::serialize(&msg) {
            Ok(bytes) => {
                if let Err(e) = self.network.broadcast(bytes).await {
                    warn!(err = %e, "failed to broadcast message to network")
                }
            }
            Err(e) => {
                warn!("Failed to serialize message; error = {e:#}")
            }
        }
    }
}
