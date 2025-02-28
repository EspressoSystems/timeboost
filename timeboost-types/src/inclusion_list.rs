use std::collections::BTreeSet;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{DelayedInboxIndex, Epoch, PriorityBundle, Timestamp, Transaction};
use sailfish_types::RoundNumber;

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InclusionList {
    round: RoundNumber,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle>,
    transactions: BTreeSet<Transaction>,
}

impl InclusionList {
    pub fn new(r: RoundNumber, t: Timestamp, i: DelayedInboxIndex) -> Self {
        Self {
            round: r,
            time: t,
            index: i,
            priority: Vec::new(),
            transactions: BTreeSet::new(),
        }
    }

    pub fn with_priority_bundles(mut self, t: Vec<PriorityBundle>) -> Self {
        self.priority = t;
        self
    }

    pub fn with_transactions<I>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = Transaction>,
    {
        self.transactions = it.into_iter().collect();
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

    pub fn len(&self) -> usize {
        self.transactions.len() + self.priority.len()
    }

    pub fn into_transactions(self) -> (Vec<PriorityBundle>, BTreeSet<Transaction>) {
        (self.priority, self.transactions)
    }

    pub fn transactions(&self) -> &BTreeSet<Transaction> {
        &self.transactions
    }

    pub fn priority_bundles(&self) -> &[PriorityBundle] {
        &self.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.index
    }
}

impl Committable for InclusionList {
    fn commit(&self) -> Commitment<Self> {
        let mut builder = RawCommitmentBuilder::new("InclusionList")
            .u64_field("round", self.round.into())
            .u64_field("time", self.time.into())
            .u64_field("index", self.index.into())
            .u64_field("priority", self.priority.len() as u64);
        builder = self
            .priority
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()));
        builder = builder.u64_field("transactions", self.transactions.len() as u64);
        self.transactions
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
