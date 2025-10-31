use std::{
    collections::{BTreeMap, HashSet},
    hash::Hash,
    sync::Arc,
};

use parking_lot::RwLock;
use sailfish::types::RoundNumber;

pub(super) const CACHE_SIZE: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct IncluderCache<T> {
    inner: Arc<RwLock<Inner<T>>>,
}

#[derive(Debug, Default)]
struct Inner<T> {
    round: RoundNumber,
    cache: BTreeMap<RoundNumber, HashSet<T>>,
}

impl<T: Clone + Hash + PartialEq + Eq> IncluderCache<T> {
    pub fn contains(&self, digest: &T) -> bool {
        let inner = self.inner.read();
        for hashes in inner.cache.values().rev() {
            if hashes.contains(digest) {
                return true;
            }
        }
        false
    }

    pub(super) fn len(&self) -> usize {
        self.inner.read().cache.len()
    }

    pub(super) fn clear(&self) {
        let mut inner = self.inner.write();
        inner.round = RoundNumber::default();
        inner.cache.clear()
    }

    pub(super) fn start(&self, r: RoundNumber) {
        let mut inner = self.inner.write();
        inner.round = r;
        inner.cache.entry(r).or_default();
    }

    pub(super) fn insert_if_new(&self, digest: &T) -> bool {
        let mut inner = self.inner.write();
        for hashes in inner.cache.values().rev() {
            if hashes.contains(digest) {
                return false;
            }
        }
        let round = inner.round;
        inner.cache.entry(round).or_default().insert(digest.clone());
        true
    }

    pub(super) fn end(&self) {
        let mut inner = self.inner.write();
        while inner.cache.len() > CACHE_SIZE {
            inner.cache.pop_first();
        }
    }
}
