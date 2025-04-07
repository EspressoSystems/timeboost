use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_types::{Address, Bundle, BundleVariant, Epoch, RetryList, SignedPriorityBundle};
use timeboost_types::{
    CandidateList, CandidateListBytes, DelayedInboxIndex, InclusionList, Timestamp,
};
use tracing::{error, trace};

use crate::metrics::SequencerMetrics;

const MIN_WAIT_TIME: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct BundleQueue(Arc<Mutex<Inner>>);

#[derive(Debug)]
struct Inner {
    priority_addr: Address,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: BTreeMap<Epoch, Vec<SignedPriorityBundle>>,
    regular: VecDeque<(Instant, Bundle)>,
    metrics: Arc<SequencerMetrics>,
    max_len: usize,
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
            max_len: usize::MAX,
        })))
    }

    #[allow(unused)]
    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    pub fn max_data_len(&self, n: usize) {
        self.0.lock().max_len = n
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
                            inner.priority.entry(epoch).or_default().push(b);
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
            .set(inner.priority.values().map(Vec::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
    }

    pub fn update_bundles(&self, incl: &InclusionList, retry: RetryList) {
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

        inner
            .metrics
            .queued_priority
            .set(inner.priority.values().map(Vec::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
    }
}

impl DataSource for BundleQueue {
    type Data = CandidateListBytes;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        if r.is_genesis() {
            match CandidateList::builder(Timestamp::now(), 0)
                .finish()
                .try_into()
            {
                Ok(list) => return list,
                Err(err) => {
                    error!(%err, "candidate list serialization error");
                    return CandidateListBytes::default();
                }
            }
        }

        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        let mut size_budget = inner.max_len;

        let mut priority = Vec::new();
        for b in inner
            .priority
            .get(&inner.time.epoch())
            .into_iter()
            .flatten()
        {
            let Ok(n) = bincode_len(b) else { continue };
            if n > size_budget {
                break;
            }
            size_budget -= n;
            priority.push(b.clone())
        }

        let mut regular = Vec::new();
        for (t, b) in &inner.regular {
            if now.duration_since(*t) < MIN_WAIT_TIME {
                break;
            }
            let Ok(n) = bincode_len(b) else { continue };
            if n > size_budget {
                break;
            }
            size_budget -= n;
            regular.push(b.clone())
        }

        let cl = CandidateList::builder(inner.time, inner.index)
            .with_priority_bundles(priority)
            .with_regular_bundles(regular)
            .finish();

        match cl.try_into() {
            Ok(list) => list,
            Err(err) => {
                error!(%err, "candidate list serialization error");
                CandidateListBytes::default()
            }
        }
    }
}

fn bincode_len<T>(val: T) -> Result<usize, bincode::error::EncodeError>
where
    T: serde::Serialize,
{
    use bincode::config::standard;
    use bincode::enc::write::SizeWriter;
    use bincode::serde::BorrowCompat;

    let mut w = SizeWriter::default();
    bincode::encode_into_writer(BorrowCompat(val), &mut w, standard())?;
    Ok(w.bytes_written)
}
