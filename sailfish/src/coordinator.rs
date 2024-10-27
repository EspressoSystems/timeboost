use std::{future::pending, sync::Arc, time::Duration};

use crate::{
    consensus::{Consensus, Dag},
    types::{
        comm::Comm,
        message::{Action, Message},
        NodeId, PublicKey,
    },
};

use anyhow::Result;
use async_lock::RwLock;
use futures::{future::BoxFuture, FutureExt};
use hotshot::traits::NetworkError;
use hotshot_types::data::ViewNumber;
use tokio::{
    sync::oneshot::{self},
    time::sleep,
};
use tracing::{trace, warn};

pub struct Coordinator {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: Box<dyn Comm<Err = NetworkError> + Send>,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    /// The shutdown signal for this coordinator.
    shutdown_rx: oneshot::Receiver<()>,

    #[cfg(feature = "test")]
    event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg(feature = "test")]
pub enum CoordinatorAuditEvent {
    ActionTaken(Action),
    MessageReceived(Message),
}

#[cfg(feature = "test")]
impl std::fmt::Display for CoordinatorAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionTaken(a) => write!(f, "Action taken: {a}"),
            Self::MessageReceived(m) => write!(f, "Message received: {m}"),
        }
    }
}

impl Coordinator {
    pub fn new<C>(
        id: NodeId,
        comm: C,
        cons: Consensus,
        shutdown_rx: oneshot::Receiver<()>,
        #[cfg(feature = "test")] event_sender: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    ) -> Self
    where
        C: Comm<Err = NetworkError> + Send + 'static,
    {
        Self {
            id,
            comm: Box::new(comm),
            consensus: cons,
            shutdown_rx,
            #[cfg(feature = "test")]
            event_log: event_sender,
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

        tracing::info!(id = %self.id, "Starting coordinator");
        // TODO: Restart behavior
        for action in self.consensus.go(Dag::new()) {
            self.on_action(action, &mut timer).await;
        }

        loop {
            tokio::select! { biased;
                vnr = &mut timer => {
                    for a in self.consensus.timeout(vnr) {
                        #[cfg(feature = "test")]
                        self.event_log
                            .as_ref()
                            .unwrap()
                            .write()
                            .await
                            .push(CoordinatorAuditEvent::ActionTaken(a.clone()));
                        self.on_action(a, &mut timer).await
                    }
                },
                msg = self.comm.receive() => match msg {
                    Ok(msg) => match self.on_message(&msg).await {
                        Ok(actions) => {
                            for a in actions {
                                #[cfg(feature = "test")]
                                self.event_log
                                    .as_ref()
                                    .unwrap()
                                    .write()
                                    .await
                                    .push(CoordinatorAuditEvent::ActionTaken(a.clone()));
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
                _ = &mut self.shutdown_rx => {
                    tracing::info!("Node {} received shutdown signal; exiting", self.id);
                    std::process::exit(0);
                }
            }
        }
    }

    async fn on_message(&mut self, m: &[u8]) -> Result<Vec<Action>> {
        let m: Message = bincode::deserialize(m)?;

        #[cfg(feature = "test")]
        self.event_log
            .as_ref()
            .unwrap()
            .write()
            .await
            .push(CoordinatorAuditEvent::MessageReceived(m.clone()));

        Ok(self.consensus.handle_message(m))
    }

    async fn on_action(&mut self, action: Action, timer: &mut BoxFuture<'static, ViewNumber>) {
        match action {
            Action::ResetTimer(r) => *timer = sleep(Duration::from_secs(4)).map(move |_| r).boxed(),
            Action::Deliver(_, r, src) => trace!(%r, %src, "deliver"), // TODO
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
