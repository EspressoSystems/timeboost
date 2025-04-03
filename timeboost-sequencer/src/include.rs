use std::cmp::max;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};

use multisig::Committee;
use sailfish::types::RoundNumber;
use timeboost_types::{
    Bundle, CandidateList, DelayedInboxIndex, Epoch, InclusionList, SeqNo, SignedPriorityBundle,
    Timestamp,
};
use timeboost_types::{RetryList, math};

const CACHE_SIZE: usize = 8;

#[derive(Debug)]
pub struct Outcome {
    pub(crate) ilist: InclusionList,
    pub(crate) retry: RetryList,
    pub(crate) is_valid: bool,
}

#[derive(Debug)]
pub struct Includer {
    committee: Committee,
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
    cache: BTreeMap<RoundNumber, HashSet<[u8; 32]>>,
}

impl Includer {
    pub fn new(c: Committee, i: DelayedInboxIndex) -> Self {
        Self {
            committee: c,
            round: RoundNumber::genesis(),
            time: Timestamp::default(),
            epoch: Timestamp::default().epoch(),
            seqno: SeqNo::zero(),
            index: i,
            cache: BTreeMap::new(),
        }
    }

    pub fn inclusion_list(&mut self, round: RoundNumber, lists: Vec<CandidateList>) -> Outcome {
        debug_assert!(lists.len() >= self.committee.quorum_size().get());

        self.round = round;

        while self.cache.len() > CACHE_SIZE {
            self.cache.pop_first();
        }

        // Ensure cache has an entry for this round.
        self.cache.entry(self.round).or_default();

        self.time = {
            let mut times = lists.iter().map(|cl| cl.timestamp()).collect::<Vec<_>>();
            max(self.time, math::median(&mut times).unwrap_or_default())
        };

        self.index = {
            let mut indices = lists
                .iter()
                .map(|cl| cl.delayed_inbox_index())
                .collect::<Vec<_>>();
            max(self.index, math::median(&mut indices).unwrap_or_default())
        };

        if self.epoch != self.time.epoch() {
            self.epoch = self.time.epoch();
            self.seqno = SeqNo::zero();
        }

        let mut regular: HashMap<Bundle, usize> = HashMap::new();
        let mut priority: BTreeMap<SeqNo, SignedPriorityBundle> = BTreeMap::new();
        let mut retry = RetryList::new();

        for (pbs, rbs) in lists.into_iter().map(CandidateList::into_bundles) {
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

        let bundles = priority.into_values().collect();

        let mut include = Vec::new();

        for (rb, n) in regular {
            if n > self.committee.threshold().get() {
                if self.is_unknown(&rb) {
                    self.cache
                        .entry(self.round)
                        .or_default()
                        .insert(*rb.digest());
                    include.push(rb)
                }
            } else {
                retry.add_regular(rb)
            }
        }

        let mut ilist = InclusionList::new(self.round, self.time, self.index);
        ilist
            .set_priority_bundles(bundles)
            .set_regular_bundles(include);

        Outcome {
            ilist,
            retry,
            is_valid: self.is_valid_cache(),
        }
    }

    fn is_unknown(&self, t: &Bundle) -> bool {
        for hashes in self.cache.values().rev() {
            if hashes.contains(t.digest()) {
                return false;
            }
        }
        true
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

    /// Check if the cache is valid, i.e. ends with at least 8 consecutive rounds.
    fn is_valid_cache(&self) -> bool {
        if self.cache.len() < CACHE_SIZE {
            return false;
        }
        self.cache
            .keys()
            .rev()
            .zip(self.cache.keys().rev().skip(1))
            .take(CACHE_SIZE)
            .all(|(a, b)| a.saturating_sub(1) == **b)
    }
}
