use crate::types::block_header::BlockHeader;
use anyhow::{ensure, Result};
use committable::Committable;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Transaction {
    bytes: Vec<u8>,
}

impl Committable for Transaction {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Transaction")
            .var_size_field("bytes", self.bytes.as_slice())
            .finalize()
    }
}

impl TryFrom<Vec<u8>> for Transaction {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(
            data.len() <= u32::MAX as usize,
            "Transaction data length exceeds u32::MAX"
        );
        Ok(Self { bytes: data })
    }
}

impl Transaction {
    /// Encode a list of transactions into bytes.
    pub fn encode(transactions: &[Self]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for txn in transactions {
            // Concatenate the bytes of the transaction size and the transaction itself.
            encoded.extend_from_slice(&txn.as_bytes().len().to_le_bytes());
            encoded.extend_from_slice(txn.as_bytes());
        }

        encoded
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BlockPayload {
    pub transactions: Vec<Transaction>,
}

impl Committable for BlockPayload {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Payload")
            .var_size_field("transactions", &Transaction::encode(&self.transactions))
            .finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Block {
    pub header: BlockHeader,
    pub payload: BlockPayload,
}

impl Committable for Block {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Block")
            .field("header", self.header.commit())
            .field("payload", self.payload.commit())
            .finalize()
    }
}

impl Default for Block {
    fn default() -> Self {
        Block::empty()
    }
}

impl Block {
    pub fn empty() -> Self {
        Self {
            header: BlockHeader {},
            payload: BlockPayload {
                transactions: vec![],
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.payload.transactions.is_empty()
    }
}
