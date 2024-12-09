use crate::types::time::Epoch;
use crate::types::transaction::Transaction;
use crate::types::{block_header::BlockHeader, time::Timestamp};
use anyhow::Result;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use timeboost_utils::types::round_number::RoundNumber;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SailfishBlock {
    header: BlockHeader,
    payload: Vec<Transaction>,
    delayed_inbox_index: u64,
}

impl PartialOrd for SailfishBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SailfishBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Ties are broken first by timestamp, then by round number, then by delayed inbox index, then by payload.
        self.header
            .timestamp()
            .cmp(&other.header.timestamp())
            .then(self.header.round().cmp(&other.header.round()))
            .then(self.delayed_inbox_index.cmp(&other.delayed_inbox_index))
            .then(self.payload.cmp(&other.payload))
    }
}

impl Default for SailfishBlock {
    fn default() -> Self {
        Self::empty(RoundNumber::genesis(), Timestamp::now())
    }
}

impl SailfishBlock {
    pub fn new(round: RoundNumber, timestamp: Timestamp) -> Self {
        Self::empty(round, timestamp)
    }

    pub fn empty(round: RoundNumber, timestamp: Timestamp) -> Self {
        Self {
            header: BlockHeader::new(round, timestamp),
            payload: Vec::new(),
            delayed_inbox_index: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub fn has_priority_transactions(&self) -> bool {
        self.payload.iter().any(|t| t.is_priority())
    }

    pub fn epoch(&self) -> Epoch {
        self.header.timestamp().into_epoch()
    }

    pub fn is_valid(&self) -> bool {
        if self.has_priority_transactions() {
            self.payload.iter().all(|t| t.is_valid())
        } else {
            true
        }
    }

    pub fn len(&self) -> usize {
        self.payload.len()
    }

    pub fn size_bytes(&self) -> usize {
        self.header.size_bytes() + self.payload.iter().map(|t| t.size_bytes()).sum::<usize>()
    }

    pub fn with_transactions(mut self, ts: Vec<Transaction>) -> Self {
        self.payload = ts;
        self
    }

    pub fn add_transactions<I>(&mut self, it: I) -> Result<()>
    where
        I: IntoIterator<Item = Transaction>,
    {
        for t in it {
            self.payload.push(t)
        }

        Ok(())
    }

    pub fn round_number(&self) -> RoundNumber {
        self.header.round()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.header.timestamp()
    }

    pub fn into_transactions(self) -> Vec<Transaction> {
        self.payload
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.payload
    }

    pub fn delayed_inbox_index(&self) -> u64 {
        self.delayed_inbox_index
    }

    pub fn set_delayed_inbox_index(&mut self, index: u64) {
        self.delayed_inbox_index = index;
    }
}

impl Committable for SailfishBlock {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Block")
            .field("header", self.header.commit())
            .u64_field("payload", self.payload.len() as u64);

        self.payload
            .iter()
            .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
            .finalize()
    }
}
