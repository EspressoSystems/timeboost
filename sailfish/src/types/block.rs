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
            .constant_str("transaction")
            .var_size_bytes(self.bytes.as_slice())
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
    ///
    /// # Errors
    /// If the transaction length conversion fails.
    pub fn encode(transactions: &[Self]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for txn in transactions {
            // Concatenate the bytes of the transaction size and the transaction itself.
            encoded.extend(txn.as_bytes().len().to_le_bytes());
            encoded.extend(&txn.bytes);
        }

        encoded
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Payload {
    pub transactions: Vec<Transaction>,
}

impl Committable for Payload {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Payload")
            .field(
                "transactions",
                // This unwrap is safe because we know that the encoding of the transactions will
                // never fail due to the above requirement that the transaction length is less than
                // u32::MAX always.
                Transaction::try_from(Transaction::encode(&self.transactions))
                    .unwrap()
                    .commit(),
            )
            .finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Block {
    header: BlockHeader,
    payload: Payload,
}

impl Committable for Block {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Block")
            .field("header", self.header.commit())
            .field("payload", self.payload.commit())
            .finalize()
    }
}
