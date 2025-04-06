use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_types::{
    Address, Bundle, BundleVariant, Epoch, RetryList, SeqNo, SignedPriorityBundle,
};
use timeboost_types::{CandidateList, DelayedInboxIndex, InclusionList, Timestamp};
use tracing::trace;

use super::Mode;
use crate::metrics::SequencerMetrics;

const MIN_WAIT_TIME: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct BundleQueue(Arc<Mutex<Inner>>);

#[derive(Debug)]
struct Inner {
    priority_addr: Address,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: BTreeMap<Epoch, BTreeMap<SeqNo, SignedPriorityBundle>>,
    regular: VecDeque<(Instant, Bundle)>,
    metrics: Arc<SequencerMetrics>,
    mode: Mode,
}

impl Inner {
    fn set_time(&mut self, time: Timestamp) {
        if time > self.time {
            if time.epoch() > self.time.epoch() {
                self.priority = self.priority.split_off(&time.epoch());
            }
            self.time = time;
            self.metrics.time.set(u64::from(self.time) as usize);
        }
    }
}

impl BundleQueue {
    pub fn new(prio: Address, idx: DelayedInboxIndex, metrics: Arc<SequencerMetrics>) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            priority_addr: prio,
            time: Timestamp::now(),
            index: idx,
            priority: BTreeMap::new(),
            regular: VecDeque::new(),
            metrics,
            mode: Mode::Passive,
        })))
    }

    #[allow(unused)]
    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    pub fn add_bundles<I>(&self, it: I)
    where
        I: IntoIterator<Item = BundleVariant>,
    {
        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);
        let epoch_now = inner.time.epoch();
        for b in it.into_iter() {
            match b {
                BundleVariant::Regular(b) => inner.regular.push_back((now, b)),
                BundleVariant::Priority(b) => {
                    match b.validate(epoch_now, Some(inner.priority_addr)) {
                        Ok(_) => {
                            let epoch = b.bundle().epoch();
                            inner
                                .priority
                                .entry(epoch)
                                .or_default()
                                .insert(b.seqno(), b);
                        }
                        Err(e) => {
                            trace!(signer = ?b.sender(), err = %e, "bundle validation failed")
                        }
                    }
                }
            }
        }

        inner
            .metrics
            .queued_priority
            .set(inner.priority.values().map(BTreeMap::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
    }

    pub fn set_mode(&self, m: Mode) {
        self.0.lock().mode = m
    }

    pub fn update_bundles(&self, incl: &InclusionList, retry: RetryList) {
        let time = Timestamp::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        // Retain priority bundles not in the inclusion list.
        if let Some(bundles) = inner.priority.get_mut(&incl.epoch()) {
            incl.priority_bundles().iter().for_each(|b| {
                bundles.remove(&b.seqno());
            });
        }

        // Retain regular bundles not in the inclusion list.
        inner
            .regular
            .retain(|(_, t)| !incl.regular_bundles().contains(t));

        // Process bundles that should be retried:
        let (priority, regular) = retry.into_parts();

        let earliest = inner
            .regular
            .front()
            .map(|(t, _)| *t)
            .unwrap_or_else(Instant::now);

        let current_epoch = inner.time.epoch();

        for b in regular {
            if b.epoch() + 1 < current_epoch {
                // Transactions that have not progressed in the protocol for
                // over a minute can be discarded.
                continue;
            }
            inner.regular.push_front((earliest, b));
        }

        for b in priority {
            inner
                .priority
                .entry(b.bundle().epoch())
                .and_modify(|bundles| match bundles.entry(b.seqno()) {
                    Entry::Vacant(e) => {
                        e.insert(b.clone());
                    }
                    Entry::Occupied(mut e) => {
                        let sb = e.get_mut();
                        if b.digest() < sb.digest() {
                            *sb = b.clone();
                        }
                    }
                })
                .or_insert([(b.seqno(), b)].into());
        }

        inner
            .metrics
            .queued_priority
            .set(inner.priority.values().map(BTreeMap::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
    }
}

impl DataSource for BundleQueue {
    type Data = CandidateList;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        if r.is_genesis() || inner.mode.is_passive() {
            return CandidateList::builder(time, inner.index).finish();
        }

        let bundles = inner
            .priority
            .get(&inner.time.epoch())
            .cloned()
            .map(|map| map.into_values().collect::<Vec<_>>())
            .unwrap_or_default();

        let regular = inner
            .regular
            .iter()
            .take_while(|(t, _)| now.duration_since(*t) >= MIN_WAIT_TIME)
            .map(|(_, x)| x.clone())
            .collect();

        CandidateList::builder(inner.time, inner.index)
            .with_priority_bundles(bundles)
            .with_regular_bundles(regular)
            .finish()
    }
}
