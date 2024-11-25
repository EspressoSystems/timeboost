use std::{future::pending, time::Duration};

use crate::consensus::{Consensus, Dag};

use anyhow::Result;
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
use tokio::time::sleep;
use tracing::info;

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    timer: BoxFuture<'static, RoundNumber>,
}

impl<C: Comm> Coordinator<C> {
    pub fn new(id: NodeId, comm: C, cons: Consensus) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            timer: pending().boxed(),
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    pub async fn start(&mut self) -> Result<Vec<Action>, C::Err> {
        Ok(self.consensus.go(Dag::new(self.consensus.committee_size())))
    }

    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        tokio::select! { biased;
            vnr = &mut self.timer => Ok(self.consensus.timeout(vnr)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    pub async fn handle_tb_event(&mut self, event: TimeboostStatusEvent) -> Result<(), C::Err> {
        // TODO
        info!(%event, "received timeboost event");
        Ok(())
    }

    pub async fn execute(&mut self, action: Action) -> Result<Option<SailfishStatusEvent>, C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
                return Ok(Some(SailfishStatusEvent {
                    round: r,
                    event: SailfishEventType::RoundFinished { round: r },
                }));
            }
            Action::Deliver(_b, r, _) => {
                return Ok(Some(SailfishStatusEvent {
                    round: r,
                    event: SailfishEventType::Committed { round: r },
                }));
            }
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e)).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e)).await?;
            }
            Action::SendTimeoutCert(c) => {
                let round = c.data().round();
                self.comm.broadcast(Message::TimeoutCert(c)).await?;
                return Ok(Some(SailfishStatusEvent {
                    round,
                    event: SailfishEventType::Timeout { round },
                }));
            }
            Action::SendNoVote(to, v) => {
                self.comm.send(to, Message::NoVote(v)).await?;
            }
        }
        Ok(None)
    }

    pub async fn shutdown(&mut self) -> Result<(), C::Err> {
        self.comm.shutdown().await
    }
}
