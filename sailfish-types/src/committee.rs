use std::fmt;

use arrayvec::ArrayVec;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::Committee;
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitteeId(u64);

impl CommitteeId {
    pub const fn new(n: u64) -> Self {
        Self(n)
    }
}

impl From<u64> for CommitteeId {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<CommitteeId> for u64 {
    fn from(val: CommitteeId) -> Self {
        val.0
    }
}

impl fmt::Display for CommitteeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Committable for CommitteeId {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CommitteeId")
            .u64(self.0)
            .finalize()
    }
}

/// A small collection of committees.
#[derive(Debug, Default, Clone)]
pub struct CommitteeVec<const N: usize> {
    vec: ArrayVec<(CommitteeId, Committee), N>,
}

impl<const N: usize> CommitteeVec<N> {
    /// Create a new empty committee collection.
    pub fn new() -> Self {
        Self {
            vec: ArrayVec::new(),
        }
    }

    /// Check if an entry for the given ID exists.
    pub fn contains(&self, id: CommitteeId) -> bool {
        self.vec.iter().any(|(i, _)| *i == id)
    }

    /// Get the committee corresponding to the given ID (if any).
    pub fn get(&self, id: CommitteeId) -> Option<&Committee> {
        self.vec.iter().find_map(|(i, c)| (*i == id).then_some(c))
    }

    /// Add a commmittee entry.
    ///
    /// If an entry with the given ID already exists, `add` is a NOOP.
    /// This method will remove the oldest entry when at capacity.
    pub fn add(&mut self, id: CommitteeId, c: Committee) {
        if self.contains(id) {
            return;
        }
        self.vec.truncate(N.saturating_sub(1));
        self.vec.insert(0, (id, c));
    }

    /// Removes a committee entry.
    pub fn remove(&mut self, id: CommitteeId) {
        self.vec.retain(|(i, _)| *i != id);
    }
}
