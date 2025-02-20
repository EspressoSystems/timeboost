use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::types::transaction::Transaction;
use crate::types::time::{Epoch, Timestamp};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SailfishBlock(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "SailfishBlock")]
struct Inner {
    time: Timestamp,
    payload: Vec<Transaction>,
    delayed_inbox_index: u64,
}

impl SailfishBlock {
    pub fn new(
        timestamp: Timestamp,
        transactions: Vec<Transaction>,
        delayed_inbox_index: u64,
    ) -> Self {
        Self(Arc::new(Inner {
            time: timestamp,
            payload: transactions,
            delayed_inbox_index,
        }))
    }

    pub fn empty(timestamp: Timestamp, delayed_inbox_index: u64) -> Self {
        Self::new(timestamp, Vec::new(), delayed_inbox_index)
    }

    pub fn is_empty(&self) -> bool {
        self.0.payload.is_empty()
    }

    pub fn has_priority_transactions(&self) -> bool {
        self.0.payload.iter().any(|t| t.is_priority())
    }

    pub fn epoch(&self) -> Epoch {
        self.0.time.epoch()
    }

    pub fn len(&self) -> usize {
        self.0.payload.len()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.0.time
    }

    pub fn into_transactions(self) -> Vec<Transaction> {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => inner.payload,
            Err(arc) => arc.payload.clone(),
        }
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.0.payload
    }

    pub fn delayed_inbox_index(&self) -> u64 {
        self.0.delayed_inbox_index
    }
}

impl Committable for SailfishBlock {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Block")
            .u64_field("time", *self.0.time)
            .u64_field("dii", self.0.delayed_inbox_index)
            .u64_field("payload", self.0.payload.len() as u64);

        self.0
            .payload
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
