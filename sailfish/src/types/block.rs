use crate::types::block_header::BlockHeader;
use committable::Committable;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Transaction(Vec<u8>);

impl Committable for Transaction {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("Transaction")
            .constant_str("transaction")
            .var_size_bytes(self.0.as_slice())
            .finalize()
    }
}
impl Transaction {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Encode a list of transactions into bytes.
    ///
    /// # Errors
    /// If the transaction length conversion fails.
    pub fn encode(transactions: &[Self]) -> Vec<u8> {
        let mut encoded = Vec::new();

        for txn in transactions {
            // The transaction length is converted from `usize` to `u32` to ensure consistent
            // number of bytes on different platforms.
            let txn_size = u32::try_from(txn.0.len())
                .expect("Invalid transaction length")
                .to_le_bytes();

            // Concatenate the bytes of the transaction size and the transaction itself.
            encoded.extend(txn_size);
            encoded.extend(&txn.0);
        }

        encoded
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
                Transaction::new(Transaction::encode(&self.transactions)).commit(),
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
