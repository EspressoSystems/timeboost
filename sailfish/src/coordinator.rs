use std::{future::pending, time::Duration};

use committable::Committable;
use futures::{FutureExt, future::BoxFuture};
use multisig::PublicKey;
use sailfish_consensus::{Consensus, Dag};
use sailfish_types::{Action, Comm, Evidence, Message, RoundNumber};
use tokio::select;
use tokio::time::sleep;

pub struct Coordinator<T: Committable, C> {
    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus<T>,

    /// The timeout timer for a sailfish consensus round.
    timer: BoxFuture<'static, RoundNumber>,

    /// Have we started consensus?
    init: bool,
}

impl<T: Committable, C: Comm<T>> Coordinator<T, C> {
    /// Create a new coordinator.
    pub fn new(comm: C, cons: Consensus<T>) -> Self {
        Self {
            comm,
            consensus: cons,
            timer: pending().boxed(),
            init: false,
        }
    }

    /// The public key of this coordinator.
    pub fn public_key(&self) -> PublicKey {
        self.consensus.public_key()
    }

    /// Get the current consensus round.
    pub fn consensus_round(&self) -> RoundNumber {
        self.consensus.round()
    }
}

impl<T, C> Coordinator<T, C>
where
    C: Comm<T> + Send,
    T: Committable + Clone + PartialEq,
{
    /// Await the next sequence of consensus actions.
    ///
    /// This function will either:
    ///
    /// - timeout a sailfish round if no progress was made, or
    /// - process a validated consensus `Message` that was RBC-delivered over the network.
    pub async fn next(&mut self) -> Result<Vec<Action<T>>, C::Err> {
        if !self.init {
            self.init = true;
            return Ok(self.consensus.go(Dag::new(), Evidence::Genesis));
        }
        select! { biased;
            r = &mut self.timer => Ok(self.consensus.timeout(r)),
            m = self.comm.receive() => Ok(self.consensus.handle_message(m?)),
        }
    }

    /// Execute a given consensus `Action`.
    ///
    /// This function will handle one of the following actions:
    ///
    /// - `ResetTimer` - Reset timeout timer.
    /// - `SendProposal` - Reliably broadcast a vertex to the members in the committee.
    /// - `SendTimeout` - Multicast a timeout message to the members in the committee.
    /// - `SendTimeoutCert` - Multicast a timeout certificate to the members in the committee.
    /// - `SendNoVote` - Send a no-vote to the leader in `r + 1` for a timeout in round `r`.
    /// - `Deliver` - NOOP.
    pub async fn execute(&mut self, action: Action<T>) -> Result<(), C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
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
            Action::Gc(r) => {
                self.comm.gc(r).await?;
            }
            Action::Deliver(_) => {
                // nothing to do
            }
            Action::NextCommittee(..) => {
                // nothing to do
            }
        }
        Ok(())
    }
}
