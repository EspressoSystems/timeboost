use std::cmp::max;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};

use multisig::Committee;
use sailfish::types::RoundNumber;
use timeboost_types::{math, Hash, PriorityBundle, RetryList, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex, Epoch, InclusionList, SeqNo, Timestamp};

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
    cache: BTreeMap<RoundNumber, HashSet<Hash>>,
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

    pub fn inclusion_list(
        &mut self,
        round: RoundNumber,
        lists: Vec<CandidateList>,
    ) -> (InclusionList, RetryList) {
        debug_assert!(lists.len() >= self.committee.quorum_size().get());

        self.round = round;

        while self.cache.len() > 8 {
            self.cache.pop_first();
        }

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

        let mut transactions: HashMap<Transaction, usize> = HashMap::new();
        let mut bundles: BTreeMap<SeqNo, PriorityBundle> = BTreeMap::new();
        let mut retry = RetryList::new();

        for (bs, ts) in lists.into_iter().map(CandidateList::into_transactions) {
            for t in ts {
                *transactions.entry(t).or_default() += 1
            }
            for b in bs {
                let nonce = b.nonce();
                let epoch = nonce.to_epoch();
                if epoch < self.epoch {
                    continue;
                }
                if epoch == self.epoch {
                    match bundles.entry(nonce.to_seqno()) {
                        Entry::Vacant(e) => {
                            e.insert(b);
                        }
                        Entry::Occupied(mut e) => {
                            if b.digest() < e.get().digest() {
                                let b = e.insert(b);
                                retry.add_bundle(b);
                            } else {
                                retry.add_bundle(b);
                            }
                        }
                    }
                    continue;
                }
                if epoch == self.epoch + 1 {
                    retry.add_bundle(b)
                }
            }
        }

        if let Ok(seqno) = self.validate_bundles(&bundles) {
            self.seqno = seqno
        } else {
            bundles.clear()
        }

        let bundles = bundles.into_values().collect();

        let mut include = Vec::new();

        for (t, n) in transactions {
            if n > self.committee.threshold().get() {
                if self.is_unknown(&t) {
                    self.cache
                        .entry(self.round)
                        .or_default()
                        .insert(*t.digest());
                    include.push(t)
                }
            } else {
                retry.add_transaction(t)
            }
        }

        let mut ilist = InclusionList::new(self.round, self.time, self.index);
        ilist
            .set_priority_bundles(bundles)
            .set_transactions(include);

        (ilist, retry)
    }

    fn is_unknown(&self, t: &Transaction) -> bool {
        for hashes in self.cache.values().rev() {
            if hashes.contains(t.digest()) {
                return false;
            }
        }
        true
    }

    fn validate_bundles(&self, bundles: &BTreeMap<SeqNo, PriorityBundle>) -> Result<SeqNo, ()> {
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
