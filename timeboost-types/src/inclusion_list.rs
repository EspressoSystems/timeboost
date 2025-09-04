use crate::{Bundle, Bytes, DelayedInboxIndex, Epoch, Timestamp, bundle::SignedPriorityBundle};
use sailfish_types::{Evidence, RoundNumber};

/// List of bundles to be included, selected from `CandidateList`.
#[derive(Debug, Clone)]
pub struct InclusionList {
    // NOTE: different from sailfish's round number, monotonically increasing at timeboost
    // sequencer side, derived from the max sailfish round among all the `Candidates` included.
    round: RoundNumber,
    time: Timestamp,
    index: DelayedInboxIndex,
    evidence: Evidence,
    priority: Vec<SignedPriorityBundle>,
    regular: Vec<Bundle>,
}

impl InclusionList {
    pub fn new(r: RoundNumber, t: Timestamp, i: DelayedInboxIndex, e: Evidence) -> Self {
        Self {
            round: r,
            time: t,
            index: i,
            evidence: e,
            priority: Vec::new(),
            regular: Vec::new(),
        }
    }

    pub fn set_priority_bundles(&mut self, t: Vec<SignedPriorityBundle>) -> &mut Self {
        self.priority = t;
        self
    }

    pub fn set_regular_bundles<I>(&mut self, it: I) -> &mut Self
    where
        I: IntoIterator<Item = Bundle>,
    {
        self.regular.clear();
        self.regular.extend(it);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.regular.is_empty() && self.priority.is_empty()
    }

    /// Returns true if any one of the bundle (either priority or regular) is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.priority_bundles()
            .iter()
            .any(|pb| pb.bundle().is_encrypted())
            || self.regular_bundles().iter().any(|b| b.is_encrypted())
    }

    pub fn has_priority_bundles(&self) -> bool {
        !self.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.time.into()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.time
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn len(&self) -> usize {
        self.regular.len() + self.priority.len()
    }

    pub fn into_bundles(self) -> (Vec<SignedPriorityBundle>, Vec<Bundle>) {
        (self.priority, self.regular)
    }

    pub fn regular_bundles(&self) -> &[Bundle] {
        &self.regular
    }

    pub fn regular_bundles_mut(&mut self) -> &mut [Bundle] {
        &mut self.regular
    }

    pub fn priority_bundles(&self) -> &[SignedPriorityBundle] {
        &self.priority
    }

    pub fn priority_bundles_mut(&mut self) -> &mut [SignedPriorityBundle] {
        &mut self.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.index
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.round.u64().to_be_bytes());
        h.update(&u64::from(self.time).to_be_bytes());
        h.update(&u64::from(self.index).to_be_bytes());
        h.finalize().into()
    }

    /// scan through the inclusion list and extract the relevant ciphertext from encrypted
    pub fn filter_ciphertexts(&self) -> impl Iterator<Item = &Bytes> {
        self.priority_bundles()
            .iter()
            .filter(move |pb| pb.bundle().is_encrypted())
            .map(|pb| pb.bundle().data())
            .chain(
                self.regular_bundles()
                    .iter()
                    .filter(move |b| b.is_encrypted())
                    .map(|b| b.data()),
            )
    }
}
