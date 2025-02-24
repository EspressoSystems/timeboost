use std::sync::Arc;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{DelayedInboxIndex, Epoch, PriorityBundle, Timestamp, Transaction};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateList(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename = "CandidateList")]
struct Inner {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle>,
    transactions: Vec<Transaction>,
}

#[derive(Debug)]
pub struct Builder {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle>,
    transactions: Vec<Transaction>,
}

impl Builder {
    pub fn with_priority_bundles(mut self, t: Vec<PriorityBundle>) -> Self {
        self.priority = t;
        self
    }

    pub fn with_transactions(mut self, t: Vec<Transaction>) -> Self {
        self.transactions = t;
        self
    }

    pub fn finish(self) -> CandidateList {
        CandidateList(Arc::new(Inner {
            time: self.time,
            index: self.index,
            priority: self.priority,
            transactions: self.transactions,
        }))
    }
}

impl CandidateList {
    pub fn builder<N>(t: Timestamp, i: N) -> Builder
    where
        N: Into<DelayedInboxIndex>,
    {
        Builder {
            time: t,
            index: i.into(),
            transactions: Vec::new(),
            priority: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.transactions.is_empty() && self.0.priority.is_empty()
    }

    pub fn has_priority_bundles(&self) -> bool {
        !self.0.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.0.time.epoch()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.0.time
    }

    pub fn len(&self) -> usize {
        self.0.transactions.len() + self.0.priority.len()
    }

    pub fn into_transactions(self) -> (Vec<PriorityBundle>, Vec<Transaction>) {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => (inner.priority, inner.transactions),
            Err(arc) => (arc.priority.clone(), arc.transactions.clone()),
        }
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.0.transactions
    }

    pub fn priority_bundles(&self) -> &[PriorityBundle] {
        &self.0.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.0.index
    }
}

impl Committable for CandidateList {
    fn commit(&self) -> Commitment<Self> {
        let mut builder = RawCommitmentBuilder::new("CandidateList")
            .u64_field("time", self.0.time.into())
            .u64_field("index", self.0.index.into())
            .u64_field("priority", self.0.priority.len() as u64);
        builder = self
            .0
            .priority
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()));
        builder = builder.u64_field("transactions", self.0.transactions.len() as u64);
        self.0
            .transactions
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
