use std::cmp::max;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use multisig::{Committee, PublicKey};
use parking_lot::RwLock;
use sailfish::types::{Evidence, RoundNumber};
use timeboost_types::{
    Bundle, CandidateList, DelayedInboxIndex, Epoch, InclusionList, SeqNo, SignedPriorityBundle,
    Timestamp,
};
use timeboost_types::{RetryList, math};
use tracing::info;

const CACHE_SIZE: usize = 8;

#[derive(Debug)]
pub struct Outcome {
    pub(crate) ilist: InclusionList,
    pub(crate) retry: RetryList,
    pub(crate) is_valid: bool,
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug, Default)]
pub struct IncluderCache {
    cache: Arc<RwLock<(RoundNumber, BTreeMap<RoundNumber, HashSet<[u8; 32]>>)>>,
}

impl IncluderCache {
    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        let cache = self.cache.read();
        for hashes in cache.1.values().rev() {
            if hashes.contains(digest) {
                return true;
            }
        }
        false
    }

    fn len(&self) -> usize {
        self.cache.read().1.len()
    }

    fn clear(&self) {
        let mut cache = self.cache.write();
        cache.0 = RoundNumber::default();
        cache.1.clear()
    }

    fn start(&self, r: RoundNumber) {
        let mut cache = self.cache.write();
        cache.0 = r;
        cache.1.entry(r).or_default();
    }

    fn insert_if_new(&self, digest: &[u8; 32]) -> bool {
        let mut cache = self.cache.write();
        for hashes in cache.1.values().rev() {
            if hashes.contains(digest) {
                return false;
            }
        }
        let round = cache.0;
        cache.1.entry(round).or_default().insert(*digest);
        true
    }

    fn end(&self) {
        let mut cache = self.cache.write();
        while cache.1.len() > CACHE_SIZE {
            cache.1.pop_first();
        }
    }
}

#[derive(Debug)]
pub struct Includer {
    label: PublicKey,
    committee: Committee,
    next_committee: Option<(RoundNumber, Committee)>,
    /// Consensus round.
    round: RoundNumber,
    /// Consensus timestamp.
    time: Timestamp,
    /// Epoch of timestamp.
    epoch: Epoch,
    /// Max. sequence number of epoch.
    seqno: SeqNo,
    /// Consensus delayed inbox index.
    index: DelayedInboxIndex,
    /// Cache of transaction hashes for the previous 8 rounds.
    cache: IncluderCache,
}

impl Includer {
    pub fn new(label: PublicKey, cache: IncluderCache, c: Committee) -> Self {
        let now = Timestamp::default();
        Self {
            label,
            committee: c,
            next_committee: None,
            round: RoundNumber::genesis(),
            time: now,
            epoch: now.into(),
            seqno: SeqNo::zero(),
            index: 0.into(),
            cache,
        }
    }

    pub fn inclusion_list(
        &mut self,
        round: RoundNumber,
        evidence: Evidence,
        lists: Vec<(RoundNumber, CandidateList)>,
    ) -> Outcome {
        if let Some((_, c)) = self.next_committee.take_if(|(r, _)| *r <= round) {
            self.committee = c;
            self.clear_cache()
        }

        info!(node = %self.label, lists = ?lists.iter().map(|(r, _)| **r).collect::<Vec<_>>());

        debug_assert!(lists.len() >= self.committee.quorum_size().get());

        self.round = round;

        // Ensure cache has an entry for this round.
        self.cache.start(self.round);

        self.time = {
            let mut times = lists
                .iter()
                .map(|cl| u64::from(cl.1.timestamp()))
                .collect::<Vec<_>>();
            max(
                self.time.into(),
                math::median(&mut times).unwrap_or_default(),
            )
            .into()
        };

        self.index = {
            let mut indices = lists
                .iter()
                .map(|cl| u64::from(cl.1.delayed_inbox_index()))
                .collect::<Vec<_>>();
            max(
                self.index.into(),
                math::median(&mut indices).unwrap_or_default(),
            )
            .into()
        };

        if self.epoch != self.time.into() {
            self.epoch = self.time.into();
            self.seqno = SeqNo::zero();
        }

        // NOTE: in timeboost spec, regular bundles are an unordered set, thus technically a HashMap
        // is sufficient. However, ordering them simplifies the decryption phase logic at no cost,
        // thus we choose BTreeMap instead.
        let mut regular: BTreeMap<Bundle, usize> = BTreeMap::new();
        let mut priority: BTreeMap<SeqNo, SignedPriorityBundle> = BTreeMap::new();
        let mut retry = RetryList::new();

        for (pbs, rbs) in lists.into_iter().map(|(_, cl)| cl.into_bundles()) {
            for rb in rbs {
                *regular.entry(rb).or_default() += 1
            }
            for b in pbs {
                let epoch = b.bundle().epoch();
                if epoch < self.epoch {
                    continue;
                }
                if epoch == self.epoch {
                    match priority.entry(b.seqno()) {
                        Entry::Vacant(e) => {
                            e.insert(b);
                        }
                        Entry::Occupied(mut e) => {
                            if b.digest() < e.get().digest() {
                                let b = e.insert(b);
                                retry.add_priority(b);
                            } else {
                                retry.add_priority(b);
                            }
                        }
                    }
                    continue;
                }
                if epoch == self.epoch + 1 {
                    retry.add_priority(b)
                }
            }
        }

        if let Ok(seqno) = self.validate_bundles(&priority) {
            self.seqno = seqno
        } else {
            priority.clear()
        }

        let ipriority = priority.into_values().collect();

        let mut iregular = Vec::new();

        for (rb, n) in regular {
            if n > self.committee.one_honest_threshold().get() {
                if self.cache.insert_if_new(rb.digest()) {
                    iregular.push(rb)
                }
            } else if !self.cache.contains(rb.digest()) {
                retry.add_regular(rb);
            }
        }

        let mut ilist = InclusionList::new(self.round, self.time, self.index, evidence);
        ilist
            .set_priority_bundles(ipriority)
            .set_regular_bundles(iregular);

        self.cache.end();

        Outcome {
            ilist,
            retry,
            is_valid: self.cache.len() >= CACHE_SIZE,
        }
    }

    pub fn set_next_committee(&mut self, r: RoundNumber, c: Committee) {
        self.next_committee = Some((r, c))
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    fn validate_bundles(
        &self,
        bundles: &BTreeMap<SeqNo, SignedPriorityBundle>,
    ) -> Result<SeqNo, ()> {
        if bundles.is_empty() {
            return Ok(self.seqno);
        }

        // Check that first bundle sequence of an epoch starts with sequence number 0.
        if self.seqno.is_zero() && bundles.keys().next().copied() != Some(SeqNo::zero()) {
            return Err(());
        }

        // Check that subsequent bundle sequences start where the previous one ended.
        if !self.seqno.is_zero() && bundles.keys().next().copied() != Some(self.seqno + 1) {
            return Err(());
        }

        // Check that there are no gaps between sequence numbers.
        if bundles
            .keys()
            .zip(bundles.keys().skip(1))
            .any(|(x, y)| *x + 1 != *y)
        {
            return Err(());
        }

        Ok(*bundles
            .last_key_value()
            .expect("non-empty bundle sequence => last entry")
            .0)
    }
}
