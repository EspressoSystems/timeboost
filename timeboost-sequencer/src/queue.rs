use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_types::{
    Address, Bundle, BundleVariant, DkgBundle, Epoch, RetryList, SeqNo, SignedPriorityBundle,
};
use timeboost_types::{
    CandidateList, CandidateListBytes, DelayedInboxIndex, InclusionList, Timestamp,
};
use tracing::{error, trace};

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
    dkg: Option<DkgBundle>,
    metrics: Arc<SequencerMetrics>,
    max_len: usize,
    mode: Mode,
    cache: HashSet<[u8; 32]>
}

impl Inner {
    fn set_time(&mut self, time: Timestamp) {
        if time > self.time {
            if Epoch::from(time) > self.time.into() {
                self.priority = self.priority.split_off(&time.into());
            }
            self.time = time;
            self.metrics.time.set(u64::from(self.time) as usize);
        }
    }
}

impl BundleQueue {
    pub fn new(prio: Address, metrics: Arc<SequencerMetrics>) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            priority_addr: prio,
            time: Timestamp::now(),
            index: 0.into(),
            priority: BTreeMap::new(),
            regular: VecDeque::new(),
            dkg: None,
            metrics,
            max_len: usize::MAX,
            mode: Mode::Passive,
            cache: HashSet::new()
        })))
    }

    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    pub fn set_mode(&self, m: Mode) {
        self.0.lock().mode = m
    }

    pub fn set_max_data_len(&self, n: usize) {
        self.0.lock().max_len = n
    }

    pub fn add_bundle(&self, b: BundleVariant) {
        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);
        let epoch_now = inner.time.into();

        match b {
            BundleVariant::Dkg(b) => inner.dkg = Some(b),
            BundleVariant::Regular(b) => {
                if inner.cache.insert(*b.digest()) {
                    inner.regular.push_back((now, b))
                }
            }
            BundleVariant::Priority(b) => match b.validate(epoch_now, Some(inner.priority_addr)) {
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
            },
        }

        inner
            .metrics
            .queued_priority
            .set(inner.priority.values().map(BTreeMap::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
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

        // Retain regular bundles not in the inclusion list or to be retried.
        inner.regular.retain(|(_, t)| {
            !(incl.regular_bundles().contains(t) || retry.regular_bundles().contains(t))
        });

        // Remove included bundles from cache.
        for b in incl.regular_bundles() {
            inner.cache.remove(b.digest());
        }

        // Process bundles that should be retried:
        let (priority, regular) = retry.into_parts();

        let earliest = inner
            .regular
            .front()
            .map(|(t, _)| *t)
            .unwrap_or_else(Instant::now);

        let current_epoch = inner.time.into();

        for b in regular {
            if b.epoch() + 1 < current_epoch {
                // Transactions that have not progressed in the protocol for
                // over a minute can be discarded.
                inner.cache.remove(b.digest());
                continue;
            }
            inner.regular.push_front((earliest, b));
        }

        for b in priority {
            match inner.priority.entry(b.bundle().epoch()) {
                Entry::Occupied(mut bundles) => match bundles.get_mut().entry(b.seqno()) {
                    Entry::Vacant(e) => {
                        e.insert(b);
                    }
                    Entry::Occupied(mut e) => {
                        let sb = e.get_mut();
                        if b.digest() < sb.digest() {
                            *sb = b;
                        }
                    }
                },
                Entry::Vacant(bundles) => {
                    bundles.insert([(b.seqno(), b)].into());
                }
            }
        }

        inner
            .metrics
            .queued_priority
            .set(inner.priority.values().map(BTreeMap::len).sum());
        inner.metrics.queued_regular.set(inner.regular.len());
    }
}

impl DataSource for BundleQueue {
    type Data = CandidateListBytes;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        if r.is_genesis() || inner.mode.is_passive() {
            return CandidateList::builder(Timestamp::now(), inner.index)
                .with_dkg(inner.dkg.take())
                .finish()
                .try_into()
                .unwrap_or_else(|err| {
                    error!(%err, "candidate list serialization error");
                    CandidateListBytes::default()
                });
        }

        let mut size_budget = inner.max_len;

        let mut priority = Vec::new();
        for (_, b) in inner.priority.get(&inner.time.into()).into_iter().flatten() {
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

        CandidateList::builder(inner.time, inner.index)
            .with_priority_bundles(priority)
            .with_regular_bundles(regular)
            .with_dkg(inner.dkg.take())
            .finish()
            .try_into()
            .unwrap_or_else(|err| {
                error!(%err, "candidate list serialization error");
                CandidateListBytes::default()
            })
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
