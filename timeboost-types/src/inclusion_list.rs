use crate::{Bundle, DelayedInboxIndex, Epoch, Timestamp, bundle::SignedPriorityBundle};
use sailfish_types::RoundNumber;

#[derive(Debug, Clone)]
pub struct InclusionList {
    round: RoundNumber,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<SignedPriorityBundle>,
    regular: Vec<Bundle>,
}

impl InclusionList {
    pub fn new(r: RoundNumber, t: Timestamp, i: DelayedInboxIndex) -> Self {
        Self {
            round: r,
            time: t,
            index: i,
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

    pub fn has_priority_bundles(&self) -> bool {
        !self.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.time.epoch()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.time
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

    pub fn priority_bundles(&self) -> &[SignedPriorityBundle] {
        &self.priority
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
}
