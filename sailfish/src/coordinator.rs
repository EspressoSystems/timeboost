use std::{future::pending, time::Duration};

use committable::Committable;
use futures::{FutureExt, future::BoxFuture};
use multisig::{Certificate, Committee, Envelope, PublicKey, Validated};
use sailfish_consensus::{Consensus, Dag};
use sailfish_types::{Action, Comm, Evidence, HasTime, Message, RoundNumber};
use sailfish_types::{ConsensusTime, Handover, HandoverMessage};
use tokio::select;
use tokio::time::sleep;

pub struct Coordinator<T: Committable, C> {
    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus<T>,

    /// The upcoming consensus instance (if any).
    next_consensus: Option<Consensus<T>>,

    /// The timeout timer for a sailfish consensus round.
    timer: BoxFuture<'static, RoundNumber>,

    /// Have we started consensus?
    init: bool,

    /// Buffer of handover messages.
    ///
    /// If handover messages arrive before we know about the next
    /// committee we buffer them and use them as soon as `set_next_consensus`
    /// is called.
    buffer: Vec<Envelope<HandoverMessage, Validated>>,

    /// Buffer of handover certificate.
    ///
    /// If a handover certificate arrives before we know about the next
    /// committee we buffer it and use it as soon as `set_next_consensus`
    /// is called.
    cert: Option<Certificate<Handover>>,
}

impl<T: Committable, C: Comm<T>> Coordinator<T, C> {
    /// Create a new coordinator.
    pub fn new(comm: C, cons: Consensus<T>, await_handover: bool) -> Self {
        Self {
            comm,
            consensus: cons,
            next_consensus: None,
            timer: pending().boxed(),
            init: await_handover,
            buffer: Vec::new(),
            cert: None,
        }
    }

    /// Has this coordinator been initialized?
    pub fn is_init(&self) -> bool {
        self.init
    }

    /// The public key of this coordinator.
    pub fn public_key(&self) -> PublicKey {
        self.consensus.public_key()
    }

    /// Get the current consensus round.
    pub fn consensus_round(&self) -> RoundNumber {
        self.consensus.round()
    }

    /// Set the next committee and the time when it should become active.
    pub fn set_next_committee(&mut self, start: ConsensusTime, committee: Committee) {
        self.buffer
            .retain(|e| e.data().handover().data().next() == committee.id());
        if let Some(cert) = &self.cert {
            if cert.data().next() != committee.id() {
                self.cert = None
            }
        }
        self.consensus.set_next_committee(start, committee)
    }
}

impl<T, C> Coordinator<T, C>
where
    C: Comm<T> + Send,
    T: Committable + HasTime + Clone + PartialEq,
{
    /// Starts Sailfish consensus.
    ///
    /// This function initializes and starts consensus. The sequence of
    /// consensus actions is returned and `Coordinator::execute` should
    /// be applied to each one.
    pub fn init(&mut self) -> Vec<Action<T>> {
        if self.init {
            return Vec::new();
        }
        self.init = true;
        let d = Dag::new(self.consensus.committee().size());
        self.consensus.go(d, Evidence::Genesis)
    }

    /// Set the consensus instance for the next committee.
    ///
    /// The instance will be applied to any buffered handover messages or
    /// certificate, if already available. The resulting actions should be
    /// passed to `Coordinator::execute` as usual.
    pub fn set_next_consensus(&mut self, mut cons: Consensus<T>) -> Vec<Action<T>> {
        let mut actions = Vec::new();
        if let Some(cert) = self.cert.take() {
            if cert.data().next() == cons.committee().id() {
                self.buffer.clear();
                actions.extend(cons.handle_handover_cert(cert))
            }
        }
        for e in self.buffer.drain(..) {
            if e.data().handover().data().next() == cons.committee().id() {
                actions.extend(cons.handle_handover(e))
            }
        }
        self.next_consensus = Some(cons);
        actions
    }

    /// Await the next sequence of consensus actions.
    ///
    /// This function will either:
    ///
    /// - timeout a sailfish round if no progress was made, or
    /// - process a validated consensus `Message` that was RBC-delivered over the network.
    pub async fn next(&mut self) -> Result<Vec<Action<T>>, C::Err> {
        select! { biased;
            r = &mut self.timer => Ok(self.consensus.timeout(r)),
            m = self.comm.receive() => {
                let m = m?;
                let i = m.committee();

                if i == self.consensus.committee().id() {
                    return Ok(self.consensus.handle_message(m))
                }

                if let Some(consensus) = &mut self.next_consensus {
                    if i == consensus.committee().id() {
                        return Ok(consensus.handle_message(m))
                    }
                }

                // Message is for a committee we do not know yet, so we buffer it.
                match m {
                    Message::Handover(e)     => self.buffer.push(e),
                    Message::HandoverCert(c) => self.cert = Some(c),
                    _                        => {}
                }

                Ok(Vec::new())
            }
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
            Action::SendHandover(e) => {
                self.comm.broadcast(Message::Handover(e)).await?;
            }
            Action::SendHandoverCert(c) => {
                self.comm.broadcast(Message::HandoverCert(c)).await?;
            }
            Action::UseCommittee(r) => {
                if let Some(next) = self.next_consensus.take() {
                    if r.committee() == next.committee().id() {
                        self.consensus = next
                    }
                }
            }
            Action::Catchup(_) => {
                // nothing to do
            }
            Action::Deliver(_) => {
                // nothing to do
            }
        }
        Ok(())
    }
}
