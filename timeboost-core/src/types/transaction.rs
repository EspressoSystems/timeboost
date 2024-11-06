use std::mem;
use std::sync::Arc;

use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::types::seqno::SeqNo;
use crate::types::time::Epoch;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce {
    epoch: Epoch,
    seqno: SeqNo,
}

impl Nonce {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address([u8; 32]); // TODO: Address format

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransactionData {
    nonce: Nonce,
    to: Address,
    data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Transaction {
    Priority {
        nonce: Nonce,
        to: Address,
        txns: Vec<TransactionData>,
    },
    Regular {
        txn: TransactionData,
    },
}

impl Transaction {
    pub fn is_priority(&self) -> bool {
        matches!(self, Transaction::Priority { .. })
    }

    pub fn nonce(&self) -> &Nonce {
        match self {
            Self::Priority { nonce, .. } => nonce,
            Self::Regular { txn } => &txn.nonce,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransactionsQueue {
    txns: Arc<Mutex<Vec<Transaction>>>,
}

impl Default for TransactionsQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionsQueue {
    pub fn new() -> Self {
        Self {
            txns: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn transactions(&self) -> Vec<Transaction> {
        self.txns.lock().iter().cloned().collect()
    }

    pub fn add(&self, t: Transaction) {
        self.txns.lock().push(t)
    }

    pub fn append(&self, mut txns: Vec<Transaction>) {
        self.txns.lock().append(&mut txns)
    }

    pub fn take(&self) -> Vec<Transaction> {
        mem::take(&mut *self.txns.lock())
    }

    pub fn remove_if<F>(&self, pred: F)
    where
        F: Fn(&Transaction) -> bool,
    {
        self.txns.lock().retain(|t| !pred(t));
    }
}

impl Committable for Address {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Address")
            .fixed_size_bytes(&self.0)
            .finalize()
    }
}

impl Committable for Nonce {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Nonce")
            .constant_str("epoch")
            .fixed_size_bytes(&self.epoch.to_be_bytes())
            .constant_str("seqno")
            .fixed_size_bytes(&self.seqno.to_be_bytes())
            .finalize()
    }
}

impl Committable for TransactionData {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("TransactionData")
            .field("to", self.to.commit())
            .field("nonce", self.nonce.commit())
            .var_size_field("bytes", &self.data)
            .finalize()
    }
}

impl Committable for Transaction {
    fn commit(&self) -> Commitment<Self> {
        match self {
            Self::Priority { to, nonce, txns } => {
                let builder = RawCommitmentBuilder::new("Transaction::Priority")
                    .field("to", to.commit())
                    .field("nonce", nonce.commit())
                    .u64_field("txns", txns.len() as u64);
                txns.iter()
                    .fold(builder, |b, t| b.var_size_bytes(t.commit().as_ref()))
                    .finalize()
            }
            Self::Regular { txn } => RawCommitmentBuilder::new("Transaction::Regular")
                .field("txn", txn.commit())
                .finalize(),
        }
    }
}
