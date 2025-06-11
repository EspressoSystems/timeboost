use std::{future::pending, time::Duration};

use arrayvec::ArrayVec;
use committable::Committable;
use futures::{FutureExt, future::BoxFuture};
use multisig::{Committee, CommitteeId, PublicKey, Validated};
use sailfish_consensus::{Consensus, Dag};
use sailfish_types::{Action, Comm, Evidence, HasTime, Message, Round};
use sailfish_types::{ConsensusTime, Payload};
use tokio::select;
use tokio::time::sleep;

/// Max. number of consensus instances.
const MAX_CONSENSUS_INSTANCES: usize = 2;

/// Max. number of previous committee IDs to keep around.
const MAX_OLD_COMMITTEE_IDS: usize = 2;

/// Duration before a timeout happens.
const TIMEOUT_DURATION: Duration = Duration::from_secs(4);

pub struct Coordinator<T: Committable, C> {
    /// The public key of this node.
    key: PublicKey,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instances of Sailfish consensus for this coordinator.
    instances: ArrayVec<Consensus<T>, MAX_CONSENSUS_INSTANCES>,

    /// The current committee.
    current_committee: CommitteeId,

    /// Old committee IDs.
    previous_committees: ArrayVec<CommitteeId, MAX_OLD_COMMITTEE_IDS>,

    /// The timeout timer for a sailfish consensus round.
    timer: BoxFuture<'static, Round>,

    /// Coordinator state.
    state: State,

    /// Buffer of messages.
    ///
    /// If messages arrive before we know about the next committee, we buffer
    /// them and use them as soon as `set_next_consensus` is called.
    buffer: Vec<Message<T, Validated>>,
}

/// Internal coordinator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Initial state.
    ///
    /// After `Coordinator::init` is called the coordinator transitions
    /// to `State::Running`.
    Start,
    /// Coordinator starts as a new committee member.
    ///
    /// Once handover completes the coordinator transitions to
    /// `State::Running`.
    AwaitHandover,
    /// Operating state after initialization/handover.
    Running,
}

/// Events this coordinator can produce.
#[derive(Debug, Clone)]
pub enum Event<T: Committable> {
    /// A new committee is in use.
    UseCommittee(Round),
    /// Gargabe collection has been performed.
    Gc(Round),
    /// Consensus was catching up.
    Catchup(Round),
    /// Some payload is being delivered
    Deliver(Payload<T>),
}

impl<T: Committable, C: Comm<T> + Send> Coordinator<T, C> {
    /// Create a new coordinator.
    pub fn new(comm: C, cons: Consensus<T>, await_handover: bool) -> Self {
        Self {
            key: cons.public_key(),
            comm,
            current_committee: cons.committee().id(),
            previous_committees: ArrayVec::new(),
            instances: {
                let mut a = ArrayVec::new();
                a.push(cons);
                a
            },
            timer: pending().boxed(),
            state: if await_handover {
                State::AwaitHandover
            } else {
                State::Start
            },
            buffer: Vec::new(),
        }
    }

    /// Has this coordinator been initialized?
    pub fn is_init(&self) -> bool {
        matches!(self.state, State::Running | State::AwaitHandover)
    }

    /// The public key of this coordinator.
    pub fn public_key(&self) -> PublicKey {
        self.key
    }

    /// Set the next committee and the time when it should become active.
    pub async fn set_next_committee(
        &mut self,
        t: ConsensusTime,
        c: Committee,
        a: C::CommitteeInfo,
    ) -> Result<(), C::Err> {
        self.buffer.retain(|m| m.committee() == c.id());
        self.current_consensus_mut().set_next_committee(t, c.id());
        self.comm.add_committee(a).await
    }

    /// Is there a consensus instance for the given committee ID?
    pub fn contains(&self, id: CommitteeId) -> bool {
        self.instances.iter().any(|c| id == c.committee().id())
    }

    /// Get the current consensus instance.
    pub fn current_consensus(&self) -> &Consensus<T> {
        self.instances
            .iter()
            .find(|c| c.committee().id() == self.current_committee)
            .expect("current is consensus instance")
    }

    /// Mutably get the current consensus instance.
    fn current_consensus_mut(&mut self) -> &mut Consensus<T> {
        self.instances
            .iter_mut()
            .find(|c| c.committee().id() == self.current_committee)
            .expect("current is consensus instance")
    }

    /// Get the consensus instance corresponding to the given committee ID.
    pub fn consensus(&self, id: CommitteeId) -> Option<&Consensus<T>> {
        self.instances.iter().find(|c| id == c.committee().id())
    }

    /// Mutablly get the consensus instance corresponding to the given committee ID.
    fn consensus_mut(&mut self, id: CommitteeId) -> Option<&mut Consensus<T>> {
        self.instances.iter_mut().find(|c| id == c.committee().id())
    }

    /// Update the current consensus instance.
    fn update_consensus(&mut self, r: Round) -> bool {
        if self.current_committee == r.committee() {
            return false;
        }
        if self
            .previous_committees
            .iter()
            .any(|id| *id == r.committee())
        {
            // Never go back to a previous instance.
            return false;
        }
        self.instances.truncate(1);
        self.previous_committees.truncate(MAX_OLD_COMMITTEE_IDS - 1);
        self.previous_committees.insert(0, self.current_committee);
        self.current_committee = r.committee();
        debug_assert_eq!(
            self.current_committee,
            self.current_consensus().committee().id()
        );
        true
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
        if self.is_init() {
            return Vec::new();
        }
        self.state = State::Running;
        let d = Dag::new(self.current_consensus().committee().size());
        self.current_consensus_mut().go(d, Evidence::Genesis)
    }

    /// Set the consensus instance for the next committee.
    ///
    /// The instance will be applied to any buffered messages.
    /// The resulting actions should be passed to `Coordinator::execute` as usual.
    ///
    /// # Panics
    ///
    /// If a consensus instance with the same committee ID already exists.
    pub fn set_next_consensus(&mut self, mut cons: Consensus<T>) -> Vec<Action<T>> {
        assert!(!self.contains(cons.committee().id()));
        let mut actions = Vec::new();
        for m in self.buffer.drain(..) {
            if m.committee() == cons.committee().id() {
                actions.extend(cons.handle_message(m))
            }
        }
        self.instances.truncate(MAX_CONSENSUS_INSTANCES - 1);
        self.instances.insert(0, cons);
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
            r = &mut self.timer => {
                Ok(if let Some(cons) = self.consensus_mut(r.committee()) {
                    cons.timeout(r.num())
                } else {
                    Vec::new()
                })
            }
            m = self.comm.receive() => {
                let m = m?;
                let c = m.committee();

                if let Some(cons) = self.consensus_mut(c) {
                    return Ok(cons.handle_message(m))
                }

                if !self.previous_committees.contains(&c) {
                    // Message is for a committee we do not know (yet), so we buffer it.
                    self.buffer.push(m);
                }

                Ok(Vec::new())
            }
        }
    }

    /// Execute a given consensus `Action`.
    pub async fn execute(&mut self, action: Action<T>) -> Result<Option<Event<T>>, C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(TIMEOUT_DURATION).map(move |_| r).fuse().boxed();
                if self.update_consensus(r) || self.state == State::AwaitHandover {
                    self.state = State::Running;
                    self.comm.use_committee(r.committee()).await?;
                    return Ok(Some(Event::UseCommittee(r)));
                }
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
                self.comm.gc(r.num()).await?;
                return Ok(Some(Event::Gc(r)));
            }
            Action::SendHandover(e) => {
                self.comm.broadcast(Message::Handover(e)).await?;
            }
            Action::SendHandoverCert(c) => {
                self.comm.broadcast(Message::HandoverCert(c)).await?;
            }
            Action::UseCommittee(r) => {
                if self.update_consensus(r) || self.state == State::AwaitHandover {
                    self.state = State::Running;
                    self.comm.use_committee(r.committee()).await?;
                    return Ok(Some(Event::UseCommittee(r)));
                }
            }
            Action::Catchup(r) => return Ok(Some(Event::Catchup(r))),
            Action::Deliver(v) => return Ok(Some(Event::Deliver(v))),
        }
        Ok(None)
    }
}
