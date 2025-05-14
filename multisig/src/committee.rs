use std::collections::VecDeque;
use std::iter::once;
use std::num::NonZeroUsize;
use std::ops::RangeFrom;
use std::sync::Arc;

use bimap::BiBTreeMap;

use super::{KeyId, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committee {
    parties: Arc<BiBTreeMap<KeyId, PublicKey>>,
}

impl Committee {
    pub fn new<I, T>(it: I) -> Self
    where
        I: IntoIterator<Item = (T, PublicKey)>,
        T: Into<KeyId>,
    {
        let map = BiBTreeMap::from_iter(it.into_iter().map(|(i, k)| (i.into(), k)));
        assert!(!map.is_empty());
        Self {
            parties: Arc::new(map),
        }
    }

    /// Returns the size of the committee as a non-zero unsigned integer.
    pub fn size(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.parties.len()).expect("committee is not empty")
    }

    /// Returns the at-least-one-honest threshold for consensus, which is
    /// `ceil(n/3)` where `n` is the committee size.
    pub fn one_honest_threshold(&self) -> NonZeroUsize {
        let t = self.parties.len().div_ceil(3);
        NonZeroUsize::new(t).expect("ceil(n/3) with n > 0 never gives 0")
    }

    /// Computes the quorum size
    pub fn quorum_size(&self) -> NonZeroUsize {
        let q = self.parties.len() * 2 / 3 + 1;
        NonZeroUsize::new(q).expect("n + 1 > 0")
    }

    /// Retrieves the public key associated with the given key ID.
    pub fn get_key<T: Into<KeyId>>(&self, ix: T) -> Option<&PublicKey> {
        self.parties.get_by_left(&ix.into())
    }

    /// Finds the key ID for a given public key.
    pub fn get_index(&self, k: &PublicKey) -> Option<KeyId> {
        self.parties.get_by_right(k).copied()
    }

    /// Checks if a public key is part of the committee.
    pub fn contains_key(&self, k: &PublicKey) -> bool {
        self.parties.contains_right(k)
    }

    /// Returns an iterator over all entries in the committee.
    pub fn entries(&self) -> impl Iterator<Item = (KeyId, &PublicKey)> {
        self.parties.iter().map(|e| (*e.0, e.1))
    }

    /// Provides an iterator over all public keys in the committee.
    pub fn parties(&self) -> impl Iterator<Item = &PublicKey> {
        self.parties.right_values()
    }

    /// Determines the leader for a given round number using a round-robin method.
    pub fn leader(&self, round: usize) -> PublicKey {
        let i = round % self.parties.len();
        self.parties
            .right_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }

    /// Returns the key ID of the leader for a given round number.
    pub fn leader_index(&self, round: usize) -> KeyId {
        let i = round % self.parties.len();
        self.parties
            .left_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Interval<T> {
    Range(T, T),
    From(T),
}

impl<T: PartialOrd> Interval<T> {
    pub fn is_empty(&self) -> bool {
        if let Self::Range(start, end) = self {
            start >= end
        } else {
            false
        }
    }

    pub fn contains(&self, p: &T) -> bool {
        match self {
            Self::Range(start, end) => start <= p && p < end,
            Self::From(start) => start <= p,
        }
    }

    pub fn start(&self) -> &T {
        match self {
            Self::Range(start, _) => start,
            Self::From(start) => start,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommitteeSeq<I> {
    prev: VecDeque<(Interval<I>, Committee)>,
    curr: (Interval<I>, Committee),
}

impl<I> CommitteeSeq<I> {
    pub fn new(r: RangeFrom<I>, c: Committee) -> Self {
        Self {
            prev: VecDeque::new(),
            curr: (Interval::From(r.start), c),
        }
    }

    pub fn current(&self) -> &Committee {
        &self.curr.1
    }

    pub fn find<F>(&self, pred: F) -> Option<&(Interval<I>, Committee)>
    where
        F: Fn(&Interval<I>, &Committee) -> bool,
    {
        once(&self.curr)
            .chain(self.prev.iter().rev())
            .find(|(r, v)| pred(r, v))
    }

    pub fn drop_while<F>(&mut self, pred: F)
    where
        F: Fn(&Interval<I>, &Committee) -> bool,
    {
        while let Some((i, c)) = self.prev.front() {
            if pred(i, c) {
                self.prev.pop_front();
            }
        }
    }
}

impl<I: PartialOrd> CommitteeSeq<I> {
    pub fn get(&self, i: I) -> Option<&Committee> {
        self.find(|iv, _| iv.contains(&i)).map(|(_, v)| v)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("interval operlap")]
pub struct IntervalOverlap(());

impl<I: PartialOrd + Clone> CommitteeSeq<I> {
    pub fn add(&mut self, r: RangeFrom<I>, v: Committee) -> Result<(), IntervalOverlap> {
        if r.start <= *self.curr.0.start() {
            return Err(IntervalOverlap(()));
        }
        let i = Interval::Range(self.curr.0.start().clone(), r.start.clone());
        self.prev.push_back((i, self.curr.1.clone()));
        self.curr = (Interval::From(r.start), v);
        Ok(())
    }
}
