use arrayvec::ArrayVec;
use multisig::{Committee, CommitteeId};

/// A small, non-empty collection of committees.
#[derive(Debug, Default, Clone)]
#[allow(clippy::len_without_is_empty)]
pub struct CommitteeVec<const N: usize> {
    vec: ArrayVec<Committee, N>,
}

impl<const N: usize> CommitteeVec<N> {
    /// Create a committee vector with the given entry.
    pub fn new(c: Committee) -> Self {
        const { assert!(N > 0) }
        let mut this = Self {
            vec: ArrayVec::new(),
        };
        this.add(c);
        this
    }

    /// Check if an entry for the given ID exists.
    pub fn contains(&self, id: CommitteeId) -> bool {
        self.vec.iter().any(|c| c.id() == id)
    }

    /// Get the index position of the given committee ID (if any).
    ///
    /// Committees are ordered by recency, i.e. the higher the index,
    /// the older the committee.
    pub fn position(&self, id: CommitteeId) -> Option<usize> {
        self.vec.iter().position(|c| c.id() == id)
    }

    /// Get the committee corresponding to the given ID (if any).
    pub fn get(&self, id: CommitteeId) -> Option<&Committee> {
        self.vec.iter().find(|c| c.id() == id)
    }

    /// Get the first (newest) committee.
    pub fn first(&self) -> &Committee {
        self.vec.first().expect("non-empty vector")
    }

    /// Get the last (oldest) committee.
    pub fn last(&self) -> &Committee {
        self.vec.last().expect("non-empty vector")
    }

    /// Get the number of committees stored.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Add a commmittee entry.
    ///
    /// If an entry with the given ID already exists, `add` is a NOOP.
    /// This method will remove the oldest entry when at capacity.
    pub fn add(&mut self, c: Committee) {
        const { assert!(N > 0) }
        if self.contains(c.id()) {
            return;
        }
        self.vec.truncate(N.saturating_sub(1));
        self.vec.insert(0, c);
    }

    /// Like `add`, but moves `self`.
    pub fn with(mut self, c: Committee) -> Self {
        self.add(c);
        self
    }

    /// Get an iterator over all committees.
    pub fn iter(&self) -> impl Iterator<Item = &Committee> {
        self.vec.iter()
    }
}

impl<const N: usize> From<Committee> for CommitteeVec<N> {
    fn from(c: Committee) -> Self {
        const { assert!(N > 0) }
        Self::new(c)
    }
}
