use std::mem;
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
    plc: Address,
    epoch: Epoch,
    index: DelayedInboxIndex,
    curr_bundles: Vec<PriorityBundle>,
    next_bundles: Vec<PriorityBundle>,
    transactions: Vec<(Instant, Transaction)>,
}

impl TransactionsQueue {
    pub fn new(plc: Address, epoch: Epoch, idx: DelayedInboxIndex) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            plc,
            epoch,
            index: idx,
            curr_bundles: Vec::new(),
            next_bundles: Vec::new(),
            transactions: Vec::new(),
        })))
    }

    #[allow(unused)]
    pub fn set_plc(&self, plc: Address) {
        self.0.lock().plc = plc
    }

    pub fn set_delayed_inbox_index(&self, idx: DelayedInboxIndex) {
        self.0.lock().index = idx
    }

    pub fn advance_to_epoch(&self, e: Epoch) {
        let mut inner = self.0.lock();
        inner.curr_bundles = mem::take(&mut inner.next_bundles);
        inner.epoch = e
    }

    // Fig. 3, lines 10 - 21
    pub fn add_transactions<I>(&self, it: I)
    where
        I: IntoIterator<Item = Transaction>,
    {
        let now = Instant::now();

        let mut inner = self.0.lock();

        for t in it.into_iter() {
            if t.to() != inner.plc {
                inner.transactions.push((now, t));
                continue;
            }

            // TODO: Check transaction signature is valid PLC signature.

            let epoch = t.nonce().to_epoch();

            if epoch < inner.epoch || epoch > inner.epoch + 1 {
                continue;
            }

            let bundle = PriorityBundle::new(epoch, t.nonce().to_seqno(), t.into_data());

            if epoch == inner.epoch {
                inner.curr_bundles.push(bundle);
            } else {
                inner.next_bundles.push(bundle);
            }
        }
    }
}

impl DataSource for TransactionsQueue {
    type Data = CandidateList;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        if r.is_genesis() {
            return CandidateList::builder(Timestamp::now(), 0).finish();
        }

        let now = Instant::now();

        let mut inner = self.0.lock();

        let txns = if let Some(i) = inner
            .transactions
            .iter()
            .position(|(t, _)| now.duration_since(*t) >= MIN_WAIT_TIME)
        {
            let mut vec = inner.transactions.split_off(i);
            mem::swap(&mut inner.transactions, &mut vec);
            vec.into_iter().map(|(_, t)| t).collect()
        } else {
            Vec::new()
        };

        CandidateList::builder(Timestamp::now(), inner.index)
            .with_priority_bundles(mem::take(&mut inner.curr_bundles))
            .with_transactions(txns)
            .finish()
    }
}
