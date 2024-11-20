use std::{future::pending, time::Duration};

use crate::consensus::{Consensus, Dag};

use anyhow::{bail, Result};
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        block::Block,
        event::{SailfishEventType, SailfishStatusEvent, TimeboostStatusEvent},
        message::{Action, Message},
        round_number::RoundNumber,
        NodeId, PublicKey,
    },
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    watch,
};
use tokio::time::sleep;
use tracing::{info, warn};

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    /// The sailfish sender application event stream.
    sf_app_tx: Sender<SailfishStatusEvent>,

    /// The timeboost receiver application event stream.
    tb_app_rx: Receiver<TimeboostStatusEvent>,

    timer: BoxFuture<'static, RoundNumber>,

    init: bool,
}

impl<C: Comm> Coordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        cons: Consensus,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
    ) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            sf_app_tx,
            tb_app_rx,
            timer: pending().boxed(),
            init: false,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    pub async fn go(mut self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
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
                    Ok(msg) => match self.on_message(msg).await {
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
                        warn!(%e, "error deserializing network message");
                        continue;
                    }
                },
                tb_event = self.tb_app_rx.recv() => match tb_event {
                    Some(event) => {
                        self.on_application_event(event).await
                    }
                    None => {
                        // If we get here, it's a big deal.
                        bail!("Receiver disconnected while awaiting application layer messages.");
                    }
                },
                shutdown_result = shutdown_rx.changed() => {
                    tracing::info!("Node {} received shutdown signal; exiting", self.id);

                    // Shut down the network
                    self.comm.shutdown().await.expect("Failed to shut down network");

                    // Unwrap the potential error with receiving the shutdown token.
                    shutdown_result.expect("The shutdown sender was dropped before the receiver could receive the token");

                    // Return the shutdown token.
                    return Ok(());
                }
            }
        }
    }

    async fn on_message(&mut self, m: Message) -> Result<Vec<Action>> {
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
                    event: SailfishEventType::RoundFinished { round: r },
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

    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            return Ok(self.consensus.go(Dag::new(self.consensus.committee_size())));
        }

        tokio::select! { biased;
            vnr = &mut self.timer => Ok(self.consensus.timeout(vnr)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    pub async fn execute(&mut self, action: Action) -> Result<Option<Block>, C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
            }
            Action::Deliver(b, _, _) => return Ok(Some(b)),
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e.cast())).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e.cast())).await?;
            }
            Action::SendTimeoutCert(c) => {
                self.comm.broadcast(Message::TimeoutCert(c)).await?;
            }
            Action::SendNoVote(to, v) => {
                self.comm.send(to, Message::NoVote(v.cast())).await?;
            }
        }
        Ok(None)
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
