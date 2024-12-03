use crate::types::block_header::BlockHeader;
use crate::types::transaction::Transaction;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use super::{round_number::RoundNumber, time::Timestamp};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct SailfishBlock {
    header: BlockHeader,
    payload: Vec<Transaction>,
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
        }
    }

    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
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

    pub fn add_transactions<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = Transaction>,
    {
        for t in it {
            self.payload.push(t)
        }
    }

    pub fn round_number(&self) -> RoundNumber {
        self.header.round()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.header.timestamp()
    }

    pub fn transactions(self) -> Vec<Transaction> {
        self.payload
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
