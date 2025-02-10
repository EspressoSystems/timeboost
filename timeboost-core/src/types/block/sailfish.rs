use crate::types::time::Epoch;
use crate::types::transaction::Transaction;
use crate::types::{block_header::BlockHeader, time::Timestamp};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use timeboost_utils::types::round_number::RoundNumber;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SailfishBlock(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "SailfishBlock")]
struct Inner {
    header: BlockHeader,
    payload: Vec<Transaction>,
    delayed_inbox_index: u64,
}

impl SailfishBlock {
    pub fn new(
        round: RoundNumber,
        timestamp: Timestamp,
        transactions: Vec<Transaction>,
        delayed_inbox_index: u64,
    ) -> Self {
        Self(Arc::new(Inner {
            header: BlockHeader::new(round, timestamp),
            payload: transactions,
            delayed_inbox_index,
        }))
    }

    pub fn empty(round: RoundNumber, timestamp: Timestamp, delayed_inbox_index: u64) -> Self {
        Self::new(round, timestamp, Vec::new(), delayed_inbox_index)
    }

    pub fn is_empty(&self) -> bool {
        self.0.payload.is_empty()
    }

    pub fn has_priority_transactions(&self) -> bool {
        self.0.payload.iter().any(|t| t.is_priority())
    }

    pub fn epoch(&self) -> Epoch {
        self.0.header.timestamp().epoch()
    }

    pub fn len(&self) -> usize {
        self.0.payload.len()
    }

    pub fn size_bytes(&self) -> usize {
        self.0.header.size_bytes() + self.0.payload.iter().map(|t| t.size_bytes()).sum::<usize>()
    }

    pub fn round_number(&self) -> RoundNumber {
        self.0.header.round()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.0.header.timestamp()
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
            .field("header", self.0.header.commit())
            .u64_field("payload", self.0.payload.len() as u64);

        self.0
            .payload
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
