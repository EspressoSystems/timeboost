use crate::types::block_header::BlockHeader;
use crate::types::transaction::Transaction;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Block {
    header: BlockHeader,
    payload: Vec<Transaction>,
}

impl Default for Block {
    fn default() -> Self {
        Self::empty()
    }
}

impl Block {
    pub fn new() -> Self {
        Self::empty()
    }

    pub fn empty() -> Self {
        Self {
            header: BlockHeader {},
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
}

impl Committable for Block {
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
