use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_crypto::KeysetId;
use timeboost_types::{Address, Epoch, PriorityBundle, RetryList, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex, InclusionList, Timestamp};

const MIN_WAIT_TIME: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct TransactionQueue(Arc<Mutex<Inner>>);

#[derive(Debug)]
struct Inner {
    priority_addr: Address,
    time: Timestamp,
    index: DelayedInboxIndex,
    bundles: BTreeMap<Epoch, Vec<PriorityBundle>>,
    transactions: VecDeque<(Instant, Transaction)>,
}

impl Inner {
    fn set_time(&mut self, time: Timestamp) {
        if time > self.time {
            if time.epoch() > self.time.epoch() {
                self.bundles = self.bundles.split_off(&time.epoch());
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
            bundles: BTreeMap::new(),
            transactions: VecDeque::new(),
        })))
    }

    #[allow(unused)]
    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    pub fn add_transactions<I>(&self, it: I)
    where
        I: IntoIterator<Item = Transaction>,
    {
        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        inner.set_time(time);

        for mut t in it.into_iter() {
            let kid = KeysetId::try_from(t.data()).expect("first 8 data bytes are keyset id");
            t.set_keyset(kid);

            if t.to() != inner.priority_addr {
                inner.transactions.push_back((now, t));
                continue;
            }

            // TODO: Check transaction signature is valid PLC signature.

            let epoch = t.nonce().to_epoch();

            if epoch < inner.time.epoch() || epoch > inner.time.epoch() + 1 {
                continue;
            }

            inner.bundles.entry(epoch).or_default().push(t.into());
        }
    }

    pub fn update_transactions(&self, incl: &InclusionList, retry: RetryList) {
        let mut inner = self.0.lock();

        // Retain priority bundles not in the inclusion list.
        if let Some(bundles) = inner.bundles.get_mut(&incl.epoch()) {
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
            .transactions
            .retain(|(_, t)| !incl.transactions().contains(t));

        // Process transactions and bundles that should be retried:
        let (transactions, bundles) = retry.into_parts();

        let now = inner
            .transactions
            .front()
            .map(|(t, _)| *t)
            .unwrap_or_else(Instant::now);

        for t in transactions {
            inner.transactions.push_front((now, t));
        }

        for b in bundles {
            inner.bundles.entry(b.epoch()).or_default().push(b)
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
            .bundles
            .get(&inner.time.epoch())
            .cloned()
            .unwrap_or_default();

        let txns = inner
            .transactions
            .iter()
            .take_while(|(t, _)| now.duration_since(*t) >= MIN_WAIT_TIME)
            .map(|(_, x)| x.clone())
            .collect();

        CandidateList::builder(inner.time, inner.index)
            .with_priority_bundles(bundles)
            .with_transactions(txns)
            .finish()
    }
}
