use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sailfish::types::{DataSource, RoundNumber};
use timeboost_types::{Address, Epoch, PriorityBundle, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex, Timestamp};

const MIN_WAIT_TIME: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub struct TransactionsQueue(Arc<Mutex<Inner>>);

#[derive(Debug)]
struct Inner {
    priority_addr: Address,
    epoch: Epoch,
    index: DelayedInboxIndex,
    bundles: BTreeMap<Epoch, Vec<PriorityBundle>>,
    transactions: Vec<(Instant, Transaction)>,
}

impl TransactionsQueue {
    pub fn new(prio: Address, idx: DelayedInboxIndex) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            priority_addr: prio,
            epoch: Timestamp::now().epoch(),
            index: idx,
            bundles: BTreeMap::new(),
            transactions: Vec::new(),
        })))
    }

    #[allow(unused)]
    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    // Fig. 3, lines 10 - 21
    pub fn add_transactions<I>(&self, it: I)
    where
        I: IntoIterator<Item = Transaction>,
    {
        let now = Instant::now();

        let mut inner = self.0.lock();

        for t in it.into_iter() {
            if t.to() != inner.priority_addr {
                inner.transactions.push((now, t));
                continue;
            }

            // TODO: Check transaction signature is valid PLC signature.

            let epoch = t.nonce().to_epoch();

            if epoch < inner.epoch || epoch > inner.epoch + 1 {
                continue;
            }

            let bundle = PriorityBundle::new(epoch, t.nonce().to_seqno(), t.into_data());

            inner.bundles.entry(epoch).or_default().push(bundle);
        }
    }
}

impl DataSource for TransactionsQueue {
    type Data = CandidateList;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        if r.is_genesis() {
            return CandidateList::builder(Timestamp::now(), 0).finish();
        }

        let time = Timestamp::now();
        let now = Instant::now();

        let mut inner = self.0.lock();

        if time.epoch() > inner.epoch {
            inner.bundles = inner.bundles.split_off(&time.epoch());
            inner.epoch = time.epoch();
        }

        let bundles = inner.bundles.get(&inner.epoch).cloned().unwrap_or_default();

        let txns = inner
            .transactions
            .iter()
            .take_while(|(t, _)| now.duration_since(*t) >= MIN_WAIT_TIME)
            .map(|(_, x)| x.clone())
            .collect();

        CandidateList::builder(time, inner.index)
            .with_priority_bundles(bundles)
            .with_transactions(txns)
            .finish()
    }
}
