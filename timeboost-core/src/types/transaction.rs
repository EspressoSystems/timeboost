use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::types::seqno::SeqNo;
use crate::types::time::Epoch;

/// Cap on transactions in a given sailfish block
const MAX_TXNS: usize = 50;

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

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<Nonce>()
    }

    pub fn now(seqno: SeqNo) -> Self {
        Self {
            epoch: Epoch::now(),
            seqno,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address([u8; 32]); // TODO: Address format
impl Address {
    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<Address>()
    }

    pub fn zero() -> Self {
        Self([0; 32])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransactionData {
    nonce: Nonce,
    to: Address,
    data: Vec<u8>,
}

impl TransactionData {
    pub fn new(nonce: Nonce, to: Address, data: Vec<u8>) -> Self {
        Self { nonce, to, data }
    }

    pub fn size_bytes(&self) -> usize {
        self.nonce.size_bytes() + self.to.size_bytes() + self.data.len()
    }
}

// TODO: Add equality check based on the spec.
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

    pub fn size_bytes(&self) -> usize {
        match self {
            Self::Priority { txns, .. } => txns.iter().map(|t| t.size_bytes()).sum(),
            Self::Regular { txn } => txn.size_bytes(),
        }
    }

    /// TODO: This will check that the transaction was signed by the PLC.
    pub fn is_valid(&self) -> bool {
        true
    }

    pub fn to(&self) -> &Address {
        match self {
            Self::Priority { to, .. } => to,
            Self::Regular { txn } => &txn.to,
        }
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self {
            // Priority transactions don't have a clean data representation.
            Self::Priority { .. } => None,
            Self::Regular { txn } => Some(&txn.data),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionsQueue {
    txns: Vec<Transaction>,
}

impl Default for TransactionsQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionsQueue {
    pub fn new() -> Self {
        Self { txns: Vec::new() }
    }

    pub fn transactions(&self) -> Vec<Transaction> {
        self.txns.clone()
    }

    pub fn add(&mut self, t: Transaction) {
        self.txns.push(t);
    }

    pub fn append(&mut self, mut txns: Vec<Transaction>) {
        self.txns.append(&mut txns);
    }

    pub fn take(&mut self) -> Vec<Transaction> {
        let limit = self.txns.len().min(MAX_TXNS);
        let mut part = self.txns.split_off(limit);
        std::mem::swap(&mut part, &mut self.txns);
        part
    }

    pub fn remove_if<F>(&mut self, pred: F)
    where
        F: Fn(&Transaction) -> bool,
    {
        self.txns.retain(|t| !pred(t));
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
