use std::mem;

use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use timeboost_crypto::traits::signature_key::SignatureKey;

use crate::types::time::Epoch;
use crate::types::{seqno::SeqNo, Keypair};

use super::{PublicKey, Signature};

lazy_static! {
    static ref PLC_PUBLIC_KEY: PublicKey =
        PublicKey::generated_from_seed_indexed(Keypair::ZERO_SEED, 0).0;
}

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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address([u8; 32]); // TODO: Address format
impl Address {
    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<Address>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransactionData {
    nonce: Nonce,
    to: Address,
    data: Bytes,
}

impl TransactionData {
    pub fn size_bytes(&self) -> usize {
        self.nonce.size_bytes() + self.to.size_bytes() + self.data.len()
    }
}

// TODO: Add equality check based on the spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Transaction {
    Priority {
        txn: TransactionData,
        sig: Signature,
    },
    Regular {
        txn: TransactionData,
    },
}

impl PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Transaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Priority { txn: txn1, .. }, Self::Priority { txn: txn2, .. }) => {
                txn1.nonce.cmp(&txn2.nonce)
            }
            (Self::Priority { .. }, Self::Regular { .. }) => std::cmp::Ordering::Less,
            (Self::Regular { .. }, Self::Priority { .. }) => std::cmp::Ordering::Greater,
            (Self::Regular { txn: txn1 }, Self::Regular { txn: txn2 }) => {
                txn1.nonce.cmp(&txn2.nonce)
            }
        }
    }
}

impl Transaction {
    pub fn is_priority(&self) -> bool {
        matches!(self, Transaction::Priority { .. })
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Transaction::Priority { txn: _, sig } => {
                // First compute the commitment of the transaction.
                let commit = self.commit();

                // Verify that the PLC public key indeed signed this transaction.
                PLC_PUBLIC_KEY.validate(sig, commit.as_ref())
            }
            Transaction::Regular { txn: _ } => true,
        }
    }

    pub fn nonce(&self) -> &Nonce {
        match self {
            Self::Priority { txn, .. } => &txn.nonce,
            Self::Regular { txn } => &txn.nonce,
        }
    }

    pub fn size_bytes(&self) -> usize {
        match self {
            Self::Priority { txn, .. } => txn.size_bytes(),
            Self::Regular { txn } => txn.size_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        mem::take(&mut self.txns)
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
            Self::Priority { txn, sig } => {
                let sig_encoded =
                    bincode::serialize(&sig).expect("serializing signature never fails");
                RawCommitmentBuilder::new("Transaction::Priority")
                    .field("txn", txn.commit())
                    .var_size_field("sig", &sig_encoded)
                    .finalize()
            }
            Self::Regular { txn } => RawCommitmentBuilder::new("Transaction::Regular")
                .field("txn", txn.commit())
                .finalize(),
        }
    }
}
