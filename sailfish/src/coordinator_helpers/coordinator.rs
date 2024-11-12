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

#[cfg(feature = "test")]
use super::test_coordinator::CoordinatorAuditEvent;
#[cfg(feature = "test")]
use crate::coordinator_helpers::interceptor::NetworkMessageInterceptor;

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
}

impl<C: Comm> Coordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        cons: Consensus,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
    ) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            shutdown_rx,
            sf_app_tx,
            tb_app_rx,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
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

    async fn on_message(&mut self, m: &[u8]) -> Result<Vec<Action>> {
        let m: Message = bincode::deserialize(m)?;

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
                let round = **c.data();
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

    async fn application_broadcast(&mut self, event: SailfishStatusEvent) {
        if let Err(e) = self.sf_app_tx.send(event).await {
            warn!(%e, "failed to send message to application layer");
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

#[cfg(feature = "test")]
impl<C: Comm> Coordinator<C> {
    #[cfg(feature = "test")]
    pub async fn append_test_event(
        &self,
        event_log: &mut Arc<RwLock<Vec<super::test_coordinator::CoordinatorAuditEvent>>>,
        event: super::test_coordinator::CoordinatorAuditEvent,
    ) {
        event_log.as_ref().write().await.push(event);
    }

    #[cfg(feature = "test")]
    pub async fn go_test(
        mut self,
        event_log: &mut Arc<RwLock<Vec<CoordinatorAuditEvent>>>,
        interceptor: Arc<NetworkMessageInterceptor>,
    ) -> ShutdownToken {
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
                        self.append_test_event(event_log, CoordinatorAuditEvent::ActionTaken(a.clone())).await;
                        self.on_action(a, &mut timer).await
                    }
                },
                msg = self.comm.receive() => match msg {
                    Ok(msg) => match self.intercept_message(&msg, event_log, &interceptor).await {
                        Ok(msgs) => {
                            for m in msgs {
                                for a in self.consensus.handle_message(m) {
                                    self.append_test_event(event_log, CoordinatorAuditEvent::ActionTaken(a.clone())).await;
                                    self.on_action(a, &mut timer).await
                                }
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

    #[cfg(feature = "test")]
    async fn intercept_message(
        &mut self,
        m: &[u8],
        event_log: &mut Arc<RwLock<Vec<super::test_coordinator::CoordinatorAuditEvent>>>,
        interceptor: &NetworkMessageInterceptor,
    ) -> Result<Vec<Message>> {
        let m: Message = bincode::deserialize(m)?;
        self.append_test_event(
            event_log,
            super::test_coordinator::CoordinatorAuditEvent::MessageReceived(m.clone()),
        )
        .await;
        Ok(interceptor.intercept_message(m, self.consensus.committee()))
    }
}
