use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_types::{
    Bundle, BundleVariant, Epoch, Address, PriorityBundle, RetryList, Signed,
};
use timeboost_types::{CandidateList, DelayedInboxIndex, InclusionList, Timestamp};
use tracing::trace;

const MIN_WAIT_TIME: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct TransactionQueue(Arc<Mutex<Inner>>);

#[derive(Debug)]
struct Inner {
    priority_addr: Address,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: BTreeMap<Epoch, Vec<PriorityBundle<Signed>>>,
    regular: VecDeque<(Instant, Bundle)>,
}

impl Inner {
    fn set_time(&mut self, time: Timestamp) {
        if time > self.time {
            if time.epoch() > self.time.epoch() {
                self.priority = self.priority.split_off(&time.epoch());
            }
            self.time = time;
        }
    }
}

impl TransactionQueue {
    pub fn new(prio: Address, idx: DelayedInboxIndex) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            priority_addr: prio,
            time: Timestamp::now(),
            index: idx,
            priority: BTreeMap::new(),
            regular: VecDeque::new(),
        })))
    }

    pub fn len(&self) -> (usize, usize) {
        let inner = self.0.lock();
        (
            inner.priority.values().map(Vec::len).sum(),
            inner.regular.len(),
        )
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
                BundleVariant::Priority(b)
                    // TODO: Check auction contract address on bundle
                    if b.validate(epoch_now, Some(inner.priority_addr)).is_ok() =>
                {
                    let epoch = b.bundle().epoch();
                    if epoch >= epoch_now && epoch <= epoch_now + 1 {
                        inner.priority.entry(epoch).or_default().push(b);
                    }
                }
                BundleVariant::Priority(b) => {
                    trace!(
                        "bundle auction address: {:?}, did not match current address: {:?}",
                        b.auction(),
                        &inner.priority_addr
                    );
                }
            }
        }
    }

    pub fn update_transactions(&self, incl: &InclusionList, retry: RetryList) {
        let mut inner = self.0.lock();

        // Retain priority bundles not in the inclusion list.
        if let Some(bundles) = inner.priority.get_mut(&incl.epoch()) {
            bundles.retain(|b| {
                if let Ok(i) = incl
                    .priority_bundles()
                    .binary_search_by_key(&b.seqno(), |x| x.seqno())
                {
                    incl.priority_bundles()[i] != *b
                } else {
                    true
                }
            });
        }

        // Retain transactions not in the inclusion list.
        inner
            .regular
            .retain(|(_, t)| !incl.regular_bundles().contains(t));

        // Process transactions and bundles that should be retried:
        let (priority, regular) = retry.into_parts();

        let now = inner
            .regular
            .front()
            .map(|(t, _)| *t)
            .unwrap_or_else(Instant::now);

        for t in regular {
            inner.regular.push_front((now, t));
        }

        for b in priority {
            inner
                .priority
                .entry(b.bundle().epoch())
                .or_default()
                .push(b)
        }
    }
}

impl DataSource for TransactionQueue {
    type Data = CandidateList;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        if r.is_genesis() {
            return CandidateList::builder(Timestamp::now(), 0).finish();
        }

        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        let bundles = inner
            .priority
            .get(&inner.time.epoch())
            .cloned()
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
