use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::types::transaction::Transaction;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SailfishBlock(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "SailfishBlock")]
struct Inner {
    payload: Vec<Transaction>,
}

impl SailfishBlock {
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self(Arc::new(Inner {
            payload: transactions,
        }))
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.payload.is_empty()
    }

    pub fn has_priority_transactions(&self) -> bool {
        self.0.payload.iter().any(|t| t.is_priority())
    }

    pub fn len(&self) -> usize {
        self.0.payload.len()
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
}

impl Committable for SailfishBlock {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Block")
            .u64_field("payload", self.0.payload.len() as u64);

        self.0
            .payload
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
