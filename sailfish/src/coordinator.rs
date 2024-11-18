use std::num::NonZeroUsize;
use std::sync::Arc;
use std::{future::pending, time::Duration};

use crate::{
    consensus::{Consensus, Dag},
    sailfish::ShutdownToken,
};

use async_lock::RwLock;
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        event::{SailfishEventType, SailfishStatusEvent, TimeboostStatusEvent},
        message::{Action, Message},
        round_number::RoundNumber,
        NodeId,
    },
};
use tokio::{
    sync::{mpsc, oneshot},
    task::{self, JoinHandle},
    time::sleep,
};
use tracing::{info, warn};

pub struct Coordinator<C> {
    id: NodeId,
    comm: C,
    consensus: JoinHandle<()>,
    cons_tx: mpsc::Sender<ConsensusEvent>,
    timer: BoxFuture<'static, RoundNumber>,
    init: bool,
    size: NonZeroUsize,
    admin: Admin,
}

struct Admin {
    /// The shutdown signal for this coordinator.
    shutdown_rx: oneshot::Receiver<ShutdownToken>,

    /// The sailfish sender application event stream.
    sf_app_tx: mpsc::Sender<SailfishStatusEvent>,

    /// The timeboost receiver application event stream.
    tb_app_rx: mpsc::Receiver<TimeboostStatusEvent>,

    #[cfg(feature = "test")]
    event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
}

impl Admin {
    async fn application_broadcast(&mut self, event: SailfishStatusEvent) {
        if let Err(e) = self.sf_app_tx.send(event).await {
            warn!(%e, "failed to send message to application layer");
        }
    }

    /// The coordinator has received an event from the timeboost application.
    async fn on_application_event(&mut self, event: TimeboostStatusEvent) {
        // TODO
        info!(%event, "received timeboost event");
    }
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

impl<C> Drop for Coordinator<C> {
    fn drop(&mut self) {
        self.consensus.abort()
    }
}

impl<C: Comm> Coordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        mut cons: Consensus,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: mpsc::Sender<SailfishStatusEvent>,
        tb_app_rx: mpsc::Receiver<TimeboostStatusEvent>,
        #[cfg(feature = "test")] event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    ) -> Self {
        let size = cons.committee_size();
        let (ctx, mut crx) = mpsc::channel(1);

        let handle = tokio::spawn(async move {
            loop {
                match crx.recv().await {
                    Some(ConsensusEvent::Init { dag, reply }) => {
                        let a = task::block_in_place(|| cons.go(dag));
                        let _ = reply.send(a);
                    }
                    Some(ConsensusEvent::Message { msg, reply }) => {
                        let a = task::block_in_place(|| cons.handle_message(msg));
                        let _ = reply.send(a);
                    }
                    Some(ConsensusEvent::Timeout { round, reply }) => {
                        let a = task::block_in_place(|| cons.timeout(round));
                        let _ = reply.send(a);
                    }
                    None => break,
                }
            }
        });

        Self {
            id,
            comm,
            consensus: handle,
            cons_tx: ctx,
            timer: pending().boxed(),
            init: false,
            size,
            admin: Admin {
                shutdown_rx,
                sf_app_tx,
                tb_app_rx,
                #[cfg(feature = "test")]
                event_log,
            },
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub async fn append_test_event(&mut self, event: CoordinatorAuditEvent) {
        self.admin
            .event_log
            .as_ref()
            .unwrap()
            .write()
            .await
            .push(event);
    }

    /// Convenience wrapper combining `next` and `exec`.
    ///
    /// NB: The future returned from `go` is *not* cancellation safe but must
    /// be run to completion, e.g. in a dedicated tokio task.
    pub async fn go(mut self) -> ShutdownToken {
        if !self.init {
            self.init = true;
            for a in self.start_consensus(Dag::new(self.size)).await {
                if let Err(err) = self.exec(a).await {
                    warn!(%err, "error executing action")
                }
            }
        }

        loop {
            let actions = tokio::select! { biased;
                r = &mut self.timer => {
                    self.on_timeout(r).await
                },
                m = self.comm.receive() => match m {
                    Ok(m) => {
                        #[cfg(feature = "test")]
                        self.append_test_event(CoordinatorAuditEvent::MessageReceived(m.clone()))
                            .await;
                        self.on_message(m).await
                    }
                    Err(err) => {
                        warn!(%err, "error executing action");
                        continue;
                    }
                },
                e = self.admin.tb_app_rx.recv() => match e {
                    Some(e) => {
                        self.admin.on_application_event(e).await;
                        continue;
                    }
                    None => {
                        warn!("Receiver disconnected while awaiting application layer messages.");

                        // If we get here, it's a big deal.
                        panic!("Receiver disconnected while awaiting application layer messages.");
                    }
                },
                t = &mut self.admin.shutdown_rx => {
                    return t.unwrap()
                }
            };

            for a in actions {
                #[cfg(feature = "test")]
                self.append_test_event(CoordinatorAuditEvent::ActionTaken(a.clone()))
                    .await;
                if let Err(err) = self.exec(a).await {
                    warn!(%err, "error executing action")
                }
            }
        }
    }

    /// Run a single consensus step.
    ///
    /// This either starts consensus, or awaits a message from the network,
    /// or a timeout, and has consensus give us the actions it wants to see
    /// performed.
    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            return Ok(self.start_consensus(Dag::new(self.size)).await);
        }

        tokio::select! { biased;
            rno = &mut self.timer => Ok(self.on_timeout(rno).await),
            msg = self.comm.receive() => Ok(self.on_message(msg?).await),
        }
    }

    /// The executes a single consensus action.
    ///
    /// It might result in a message broadcast, or the delivery of a block of
    /// transactions, satisfying the consensus rules.
    pub async fn exec(&mut self, action: Action) -> Result<(), C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
                // This is somewhat of a "if you know, you know" event as a reset timer
                // implies that the protocol has moved to the next round.
                self.admin
                    .application_broadcast(SailfishStatusEvent {
                        round: r,
                        event: SailfishEventType::Timeout { round: r },
                    })
                    .await;
            }
            Action::Deliver(_, r, _) => {
                self.admin
                    .application_broadcast(SailfishStatusEvent {
                        round: r,
                        event: SailfishEventType::Committed { round: r },
                    })
                    .await;
            }
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e.cast())).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e.cast())).await?;
            }
            Action::SendTimeoutCert(c) => {
                let round = c.data().round();
                self.comm.broadcast(Message::TimeoutCert(c)).await?;
                self.admin
                    .application_broadcast(SailfishStatusEvent {
                        round,
                        event: SailfishEventType::Timeout { round },
                    })
                    .await;
            }
            Action::SendNoVote(to, v) => {
                self.comm.send(to, Message::NoVote(v.cast())).await?;
            }
        }
        Ok(())
    }

    async fn start_consensus(&mut self, d: Dag) -> Vec<Action> {
        let (tx, rx) = oneshot::channel();
        let event = ConsensusEvent::Init { dag: d, reply: tx };
        if self.cons_tx.send(event).await.is_ok() {
            return rx.await.unwrap_or_default();
        }
        Vec::new()
    }

    async fn on_message(&mut self, m: Message) -> Vec<Action> {
        let (tx, rx) = oneshot::channel();
        let event = ConsensusEvent::Message { msg: m, reply: tx };
        if self.cons_tx.send(event).await.is_ok() {
            return rx.await.unwrap_or_default();
        }
        Vec::new()
    }

    async fn on_timeout(&mut self, r: RoundNumber) -> Vec<Action> {
        let (tx, rx) = oneshot::channel();
        let event = ConsensusEvent::Timeout {
            round: r,
            reply: tx,
        };
        if self.cons_tx.send(event).await.is_ok() {
            return rx.await.unwrap_or_default();
        }
        Vec::new()
    }
}

enum ConsensusEvent {
    Init {
        dag: Dag,
        reply: oneshot::Sender<Vec<Action>>,
    },
    Timeout {
        round: RoundNumber,
        reply: oneshot::Sender<Vec<Action>>,
    },
    Message {
        msg: Message,
        reply: oneshot::Sender<Vec<Action>>,
    },
}
