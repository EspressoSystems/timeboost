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

    /// The timeout timer for a sailfish consensus round.
    timer: BoxFuture<'static, RoundNumber>,

    /// Have we started consensus?
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

    /// Starts Sailfish consensus.
    ///
    /// This function initializes and starts consensus. The sequence of
    /// consensus actions is returned and `Coordinator::execute` should be applied
    /// to each one.
    ///
    /// # Panics
    ///
    /// `Coordinator::start` must only be invoked once, otherwise it will panic.
    pub async fn start(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            let e = Evidence::Genesis;
            let d = Dag::new(self.consensus.committee_size());
            return Ok(self.consensus.go(d, e));
        }
        panic!("Cannot call start twice");
    }

    /// Await the next sequence of consensus actions.
    ///
    /// This function will either:
    ///
    /// - timeout a sailfish round if no progress was made, or
    /// - process a validated consensus `Message` that was RBC-delivered over the network.
    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        tokio::select! { biased;
            r = &mut self.timer => Ok(self.consensus.timeout(r)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    /// Appends a list of transactions to the consensus transaction queue.
    pub fn handle_transactions(&mut self, transactions: Vec<Transaction>) {
        for t in transactions {
            self.consensus.enqueue_transaction(t);
        }
    }

    /// Execute a given consensus `Action`.
    ///
    /// This function will handle one of the following actions:
    ///
    /// - `ResetTimer` - Reset timeout timer.
    /// - `Deliver` - Return a Sailfish consensus block to the caller.
    /// - `SendProposal` - Reliably broadcast a vertex to the members in the committee.
    /// - `SendTimeout` - Multicast a timeout message to the members in the committee.
    /// - `SendTimeoutCert` - Multicast a timeout certificate to the members in the committee.
    /// - `SendNoVote` - Send a no-vote to the leader in `r + 1` for a timeout in round `r`.
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
}
