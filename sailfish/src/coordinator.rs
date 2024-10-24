use std::{future::pending, time::Duration};

use crate::{
    consensus::Consensus,
    types::{
        comm::Comm,
        message::{Action, Message},
        NodeId, PublicKey,
    },
};

use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use hotshot::traits::NetworkError;
use hotshot_types::data::ViewNumber;
use tokio::time::sleep;
use tracing::{info, warn};

pub struct Coordinator {
    id: NodeId,
    comm: Box<dyn Comm<Err = NetworkError> + Send>,
    consensus: Consensus,
}

impl Coordinator {
    pub fn new<C>(id: NodeId, comm: C, cons: Consensus) -> Self
    where
        C: Comm<Err = NetworkError> + Send + 'static,
    {
        Self {
            id,
            comm: Box::new(comm),
            consensus: cons,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    pub async fn go(mut self) -> ! {
        let mut timer: BoxFuture<'static, ViewNumber> = pending().boxed();
        loop {
            tokio::select! { biased;
                vnr = &mut timer => {
                    for a in self.consensus.timeout(vnr) {
                        self.on_action(a, &mut timer).await
                    }
                },
                msg = self.comm.receive() => match msg {
                    Ok(msg) => match self.on_message(&msg).await {
                        Ok(actions) => {
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
                }
            }
        }
    }

    async fn on_message(&mut self, m: &[u8]) -> Result<Vec<Action>> {
        let m = bincode::deserialize(m)?;
        Ok(self.consensus.handle_message(m))
    }

    async fn on_action(&mut self, action: Action, timer: &mut BoxFuture<'static, ViewNumber>) {
        match action {
            Action::ResetTimer(r) => *timer = sleep(Duration::from_secs(4)).map(move |_| r).boxed(),
            Action::Deliver(_, r, src) => info!(%r, %src, "deliver"), // TODO
            Action::SendProposal(e) => self.broadcast(Message::Vertex(e.cast())).await,
            Action::SendTimeout(e) => self.broadcast(Message::Timeout(e.cast())).await,
            Action::SendTimeoutCert(c) => self.broadcast(Message::TimeoutCert(c)).await,
            Action::SendNoVote(to, v) => self.unicast(to, Message::NoVote(v.cast())).await,
        }
    }

    async fn broadcast(&mut self, msg: Message) {
        match bincode::serialize(&msg) {
            Ok(bytes) => {
                if let Err(err) = self.comm.broadcast(bytes).await {
                    warn!(%err, "failed to broadcast message to network")
                }
            }
            Err(err) => {
                warn!(%err, "failed to serialize message")
            }
        }
    }

    async fn unicast(&mut self, to: PublicKey, msg: Message) {
        match bincode::serialize(&msg) {
            Ok(bytes) => {
                if let Err(err) = self.comm.send(to, bytes).await {
                    warn!(%err, %to, "failed to send message")
                }
            }
            Err(err) => {
                warn!(%err, %to, "failed to serialize message")
            }
        }
    }
}
