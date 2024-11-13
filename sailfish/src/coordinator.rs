use std::{future::pending, sync::Arc, time::Duration};

use crate::{
    consensus::{Consensus, Dag},
    sailfish::ShutdownToken,
};

use anyhow::Result;
use async_lock::RwLock;
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        committee::StaticCommittee,
        event::{SailfishEventType, SailfishStatusEvent, TimeboostStatusEvent},
        message::{Action, Message},
        round_number::RoundNumber,
        NodeId, PublicKey,
    },
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{
    sync::oneshot::{self},
    time::sleep,
};
use tracing::{info, warn};

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    /// The shutdown signal for this coordinator.
    shutdown_rx: oneshot::Receiver<ShutdownToken>,

    /// The sailfish sender application event stream.
    sf_app_tx: Sender<SailfishStatusEvent>,

    /// The timeboost receiver application event stream.
    tb_app_rx: Receiver<TimeboostStatusEvent>,

    #[cfg(feature = "test")]
    event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,

    #[cfg(feature = "test")]
    interceptor: Arc<NetworkMessageInterceptor>,
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

#[allow(clippy::too_many_arguments)]
impl<C: Comm> Coordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        cons: Consensus,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
        #[cfg(feature = "test")] event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
        #[cfg(feature = "test")] interceptor: Arc<NetworkMessageInterceptor>,
    ) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            shutdown_rx,
            sf_app_tx,
            tb_app_rx,
            #[cfg(feature = "test")]
            event_log,
            #[cfg(feature = "test")]
            interceptor,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    #[cfg(feature = "test")]
    pub async fn append_test_event(&mut self, event: CoordinatorAuditEvent) {
        self.event_log.as_ref().unwrap().write().await.push(event);
    }

    pub async fn go(mut self) -> ShutdownToken {
        let mut timer: BoxFuture<'static, RoundNumber> = pending().boxed();

        tracing::info!(id = %self.id, "Starting coordinator");
        // TODO: Restart behavior
        for action in self.consensus.go(Dag::new(self.consensus.committee_size())) {
            self.on_action(action, &mut timer).await;
        }

        loop {
            tokio::select! { biased;
                vnr = &mut timer => {
                    for a in self.consensus.timeout(vnr) {
                        #[cfg(feature = "test")]
                        self.append_test_event(CoordinatorAuditEvent::ActionTaken(a.clone()))
                            .await;
                        self.on_action(a, &mut timer).await
                    }
                },
                msg = self.comm.receive() => match msg {
                    Ok(msg) => match self.on_message(msg).await {
                        Ok(actions) => {
                            for a in actions {
                                #[cfg(feature = "test")]
                                self.append_test_event(CoordinatorAuditEvent::ActionTaken(a.clone()))
                                    .await;

                                self.on_action(a, &mut timer).await
                            }
                        }
                        Err(err) => {
                            warn!(%err, "error processing incoming message");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize network message; error = {e:#}");
                        continue;
                    }
                },
                tb_event = self.tb_app_rx.recv() => match tb_event {
                    Some(event) => {
                        self.on_application_event(event).await
                    }
                    None => {
                        warn!("Receiver disconnected while awaiting application layer messages.");

                        // If we get here, it's a big deal.
                        panic!("Receiver disconnected while awaiting application layer messages.");
                    }
                },
                token = &mut self.shutdown_rx => {
                    tracing::info!("Node {} received shutdown signal; exiting", self.id);
                    return token.expect("The shutdown sender was dropped before the receiver could receive the token");
                }
            }
        }
    }

    async fn on_message(&mut self, m: Message) -> Result<Vec<Action>> {
        #[cfg(feature = "test")]
        self.append_test_event(CoordinatorAuditEvent::MessageReceived(m.clone()))
            .await;

        #[cfg(feature = "test")]
        let msg = self
            .interceptor
            .intercept_message(m.clone(), self.consensus().committee());
        if msg.is_empty() {
            return Ok(Vec::new());
        }

        Ok(self.consensus.handle_message(m))
    }

    /// The coordinator has received an event from the timeboost application.
    async fn on_application_event(&mut self, event: TimeboostStatusEvent) {
        // TODO
        info!(%event, "received timeboost event");
    }

    async fn on_action(&mut self, action: Action, timer: &mut BoxFuture<'static, RoundNumber>) {
        match action {
            Action::ResetTimer(r) => {
                *timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();

                // This is somewhat of a "if you know, you know" event as a reset timer
                // implies that the protocol has moved to the next round.
                self.application_broadcast(SailfishStatusEvent {
                    round: r,
                    event: SailfishEventType::Timeout { round: r },
                })
                .await;
            }
            Action::Deliver(_, r, _) => {
                self.application_broadcast(SailfishStatusEvent {
                    round: r,
                    event: SailfishEventType::Committed { round: r },
                })
                .await;
            }
            Action::SendProposal(e) => self.broadcast(Message::Vertex(e.cast())).await,
            Action::SendTimeout(e) => self.broadcast(Message::Timeout(e.cast())).await,
            Action::SendTimeoutCert(c) => {
                let round = c.data().round();
                self.broadcast(Message::TimeoutCert(c)).await;
                self.application_broadcast(SailfishStatusEvent {
                    round,
                    event: SailfishEventType::Timeout { round },
                })
                .await;
            }
            Action::SendNoVote(to, v) => self.unicast(to, Message::NoVote(v.cast())).await,
        }
    }

    async fn broadcast(&mut self, msg: Message) {
        if let Err(err) = self.comm.broadcast(msg).await {
            warn!(%err, "failed to broadcast message to network")
        }
    }

    async fn application_broadcast(&mut self, event: SailfishStatusEvent) {
        if let Err(e) = self.sf_app_tx.send(event).await {
            warn!(%e, "failed to send message to application layer");
        }
    }

    async fn unicast(&mut self, to: PublicKey, msg: Message) {
        if let Err(err) = self.comm.send(to, msg).await {
            warn!(%err, %to, "failed to send message")
        }
    }
}

#[cfg(feature = "test")]
pub type NetworkMessageModifier =
    Arc<dyn Fn(&Message, &StaticCommittee) -> Vec<Message> + Send + Sync>;
/// Intercept a message before a node processes it and apply transformations if any provided

#[derive(Clone)]
#[cfg(feature = "test")]
pub struct NetworkMessageInterceptor {
    msg_modifier: NetworkMessageModifier,
}

#[cfg(feature = "test")]
impl NetworkMessageInterceptor {
    pub fn new<F>(msg_modifier: F) -> Self
    where
        F: Fn(&Message, &StaticCommittee) -> Vec<Message> + Send + Sync + Clone + 'static,
    {
        Self {
            msg_modifier: Arc::new(msg_modifier),
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(
        &self,
        msg: Message,
        committee: &StaticCommittee,
    ) -> Vec<Message> {
        (self.msg_modifier)(&msg, committee)
    }
}

#[cfg(feature = "test")]
impl Default for NetworkMessageInterceptor {
    fn default() -> Self {
        Self {
            msg_modifier: Arc::new(|msg: &Message, _committee: &StaticCommittee| vec![msg.clone()]),
        }
    }
}
