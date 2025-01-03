use std::num::NonZeroUsize;
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

    pub fn size(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.parties.len()).expect("Committee is not empty")
    }

    pub fn threshold(&self) -> NonZeroUsize {
        let t = self.parties.len().div_ceil(3);
        NonZeroUsize::new(t).expect("ceil(n/3) with n > 0 never gives 0")
    }
    pub fn quorum_size(&self) -> NonZeroUsize {
        let q = self.parties.len() * 2 / 3 + 1;
        NonZeroUsize::new(q).expect("n + 1 > 0")
    }

    pub fn get_key<T: Into<KeyId>>(&self, ix: T) -> Option<&PublicKey> {
        self.parties.get_by_left(&ix.into())
    }

    pub fn get_index(&self, k: &PublicKey) -> Option<KeyId> {
        self.parties.get_by_right(k).copied()
    }

    pub fn contains_key(&self, k: &PublicKey) -> bool {
        self.parties.contains_right(k)
    }

    pub fn entries(&self) -> impl Iterator<Item = (KeyId, &PublicKey)> {
        self.parties.iter().map(|e| (*e.0, e.1))
    }

    pub fn parties(&self) -> impl Iterator<Item = &PublicKey> {
        self.parties.right_values()
    }

    pub fn leader(&self, round: usize) -> PublicKey {
        let i = round % self.parties.len();
        self.parties
            .right_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }

    pub fn leader_index(&self, round: usize) -> KeyId {
        let i = round % self.parties.len();
        self.parties
            .left_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }
}
