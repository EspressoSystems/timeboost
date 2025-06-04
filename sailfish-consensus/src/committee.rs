use std::ops::Deref;

use multisig::{Certificate, Committee, Envelope, Validated, VoteAccumulator};
use sailfish_types::{CommitteeId, ConsensusTime, Handover, HandoverMessage};

/// Information about the current committee.
#[derive(Debug, Clone)]
pub struct CurrentCommittee {
    id: CommitteeId,
    val: Committee,
    state: CommitteeState,
}

impl CurrentCommittee {
    pub fn new(id: CommitteeId, c: Committee) -> Self {
        Self {
            id,
            val: c,
            state: CommitteeState::Active,
        }
    }

    pub fn pending(mut self) -> Self {
        self.state = CommitteeState::Pending;
        self
    }

    pub fn id(&self) -> CommitteeId {
        self.id
    }

    pub fn committee(&self) -> &Committee {
        &self.val
    }

    pub fn is_pending(&self) -> bool {
        self.state.is_pending()
    }

    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    pub(crate) fn state(&self) -> CommitteeState {
        self.state
    }

    pub(crate) fn set_state(&mut self, s: CommitteeState) {
        self.state = s
    }
}

impl Deref for CurrentCommittee {
    type Target = Committee;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CommitteeState {
    Pending,
    Active,
    Shutdown,
}

impl CommitteeState {
    pub(crate) fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub(crate) fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }

    pub(crate) fn is_shutdown(self) -> bool {
        matches!(self, Self::Shutdown)
    }
}

/// Information about the next committee.
#[derive(Debug, Clone)]
pub struct NextCommittee {
    pub(crate) start: ConsensusTime,
    pub(crate) id: CommitteeId,
    pub(crate) committee: Committee,
    pub(crate) handover_started: bool,
}

impl NextCommittee {
    pub fn new(start: ConsensusTime, id: CommitteeId, c: Committee) -> Self {
        Self {
            start,
            id,
            committee: c,
            handover_started: false,
        }
    }
}

/// Handover vote accumulation and buffer.
pub(crate) struct Handovers {
    /// Collect handover messages to form a certificate.
    pub(crate) votes: Option<VoteAccumulator<Handover>>,

    /// Buffer of handover messages.
    ///
    /// In case where handover messages arrive before we know about the next
    /// committee (which can only happend for members of the current committee),
    /// we buffer them and apply them as soon as `add_committee` is called.
    pub(crate) buffer: Vec<Envelope<HandoverMessage, Validated>>,

    /// Buffer of handover certificate.
    ///
    /// Same reason, why we have `buffer`, but for the handover certificate,
    /// of which there is only one.
    pub(crate) cert: Option<Certificate<Handover>>,
}

impl Handovers {
    pub(crate) fn clear(&mut self) {
        self.votes = None;
        self.cert = None;
        self.buffer.clear()
    }
}
