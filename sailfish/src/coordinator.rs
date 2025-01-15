use std::{future::pending, time::Duration};

use crate::consensus::{Consensus, Dag};

use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        event::{SailfishEventType, SailfishStatusEvent},
        message::{Action, Evidence, Message},
        transaction::Transaction,
        NodeId,
    },
};
use timeboost_utils::types::round_number::RoundNumber;
use tokio::time::sleep;

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    timer: BoxFuture<'static, RoundNumber>,

    init: bool,
}

impl<C: Comm> Coordinator<C> {
    pub fn new<N>(id: N, comm: C, cons: Consensus) -> Self
    where
        N: Into<NodeId>,
    {
        Self {
            id: id.into(),
            comm,
            consensus: cons,
            timer: pending().boxed(),
            init: false,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub async fn start(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            let e = Evidence::Genesis;
            let d = Dag::new(self.consensus.committee_size());
            return Ok(self.consensus.go(d, e));
        }
        panic!("Cannot call start twice");
    }

    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        tokio::select! { biased;
            r = &mut self.timer => Ok(self.consensus.timeout(r)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    pub fn handle_transactions(&mut self, transactions: Vec<Transaction>) {
        for t in transactions {
            self.consensus.enqueue_transaction(t);
        }
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
            Action::Deliver(b, r, _) => {
                return Ok(Some(SailfishStatusEvent {
                    round: r,
                    event: SailfishEventType::Committed { round: r, block: b },
                }));
            }
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e)).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e)).await?;
            }
            Action::SendTimeoutCert(e) => {
                let round = e.data().data().round();
                self.comm.broadcast(Message::TimeoutCert(e)).await?;
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
