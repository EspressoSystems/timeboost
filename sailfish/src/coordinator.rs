use std::{future::pending, time::Duration};

use anyhow::Result;
use committable::Committable;
use futures::{future::BoxFuture, FutureExt};
use sailfish_types::{Comm, Action, Evidence, Message, RoundNumber};
use tokio::time::sleep;

use crate::consensus::{Consensus, Dag};

pub struct Coordinator<B, C> {
    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus<B>,

    /// The timeout timer for a sailfish consensus round.
    timer: BoxFuture<'static, RoundNumber>,

    /// Have we started consensus?
    init: bool,
}

impl<B, C: Comm<B>> Coordinator<B, C> {
    pub fn new(comm: C, cons: Consensus<B>) -> Self {
        Self {
            comm,
            consensus: cons,
            timer: pending().boxed(),
            init: false,
        }
    }
}

impl<B, C: Comm<B>> Coordinator<B, C>
where
    B: Committable + Clone + Eq
{
    /// Starts Sailfish consensus.
    ///
    /// This function initializes and starts consensus. The sequence of
    /// consensus actions is returned and `Coordinator::execute` should be applied
    /// to each one.
    ///
    /// # Panics
    ///
    /// `Coordinator::start` must only be invoked once, otherwise it will panic.
    pub async fn start(&mut self) -> Vec<Action<B>> {
        assert!(!self.init, "Cannot call start twice");
        self.init = true;
        let e = Evidence::Genesis;
        let d = Dag::new(self.consensus.committee_size());
        self.consensus.go(d, e)
    }

    /// Await the next sequence of consensus actions.
    ///
    /// This function will either:
    ///
    /// - timeout a sailfish round if no progress was made, or
    /// - process a validated consensus `Message` that was RBC-delivered over the network.
    pub async fn next(&mut self) -> Result<Vec<Action<B>>, C::Err> {
        tokio::select! { biased;
            r = &mut self.timer => Ok(self.consensus.timeout(r)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    /// Appends a sequence of transactions to the consensus transaction queue.
    pub fn append_block(&mut self, block: B) {
        self.consensus.add_block(block)
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
    pub async fn execute(&mut self, action: Action<B>) -> Result<(), C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
            }
            Action::Deliver(..) => {
                // nothing todo
            }
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e)).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e)).await?;
            }
            Action::SendTimeoutCert(c) => {
                self.comm.broadcast(Message::TimeoutCert(c)).await?;
            }
            Action::SendNoVote(to, v) => {
                self.comm.send(to, Message::NoVote(v)).await?;
            }
        }
        Ok(())
    }
}
