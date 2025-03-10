use crate::{DelayedInboxIndex, Epoch, PriorityBundle, Timestamp, Transaction};
use sailfish_types::RoundNumber;

#[derive(Debug, Clone)]
pub struct InclusionList {
    round: RoundNumber,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle>,
    transactions: Vec<Transaction>,
}

impl InclusionList {
    pub fn new(r: RoundNumber, t: Timestamp, i: DelayedInboxIndex) -> Self {
        Self {
            round: r,
            time: t,
            index: i,
            priority: Vec::new(),
            transactions: Vec::new(),
        }
    }

    pub fn set_priority_bundles(&mut self, t: Vec<PriorityBundle>) -> &mut Self {
        self.priority = t;
        self
    }

    pub fn set_transactions<I>(&mut self, it: I) -> &mut Self
    where
        I: IntoIterator<Item = Transaction>,
    {
        self.transactions.clear();
        self.transactions.extend(it);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.priority.is_empty()
    }

    pub fn has_priority_bundles(&self) -> bool {
        !self.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.time.epoch()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.time
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn len(&self) -> usize {
        self.transactions.len() + self.priority.len()
    }

    pub fn into_transactions(self) -> (Vec<PriorityBundle>, Vec<Transaction>) {
        (self.priority, self.transactions)
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn priority_bundles(&self) -> &[PriorityBundle] {
        &self.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.index
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.round.u64().to_be_bytes());
        h.update(&u64::from(self.time).to_be_bytes());
        h.update(&u64::from(self.index).to_be_bytes());
        for b in &self.priority {
            h.update(&b.digest()[..]);
        }
        for t in &self.transactions {
            h.update(&t.digest()[..]);
        }
        h.finalize().into()
    }
}
