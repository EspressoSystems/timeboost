use alloy_primitives::B256;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::Transaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block(alloy_consensus::Block<Transaction>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHash(B256);

impl std::ops::Deref for BlockHash {
    type Target = B256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for BlockHash {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("BlockHash")
            .fixed_size_field("block-hash", &self.0)
            .finalize()
    }
}
