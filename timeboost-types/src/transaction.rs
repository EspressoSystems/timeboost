use std::collections::BTreeSet;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Address, Epoch, SeqNo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce([u8; 32]);

impl Nonce {
    pub fn to_epoch(self) -> Epoch {
        let n = u128::from_be_bytes(self.0[..16].try_into().expect("16 bytes = 128 bit"));
        Epoch::from(n)
    }

    pub fn to_seqno(self) -> SeqNo {
        let n = u128::from_be_bytes(self.0[16..].try_into().expect("16 bytes = 128 bit"));
        SeqNo::from(n)
    }
}

impl From<[u8; 32]> for Nonce {
    fn from(val: [u8; 32]) -> Self {
        Self(val)
    }
}

impl From<Nonce> for [u8; 32] {
    fn from(val: Nonce) -> Self {
        val.0
    }
}

impl Committable for Nonce {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Nonce")
            .fixed_size_bytes(&self.0)
            .finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Transaction {
    to: Address,
    nonce: Nonce,
    data: Vec<u8>,
    hash: [u8; 32],
}

impl Transaction {
    pub fn new(nonce: Nonce, to: Address, data: Vec<u8>) -> Self {
        let h = blake3::hash(&data);
        Self {
            nonce,
            to,
            data,
            hash: h.into(),
        }
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn to(&self) -> Address {
        self.to
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl Committable for Transaction {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Transaction")
            .field("to", self.to.commit())
            .field("nonce", self.nonce.commit())
            .var_size_field("data", &self.data)
            .finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PriorityBundle {
    epoch: Epoch,
    seqno: SeqNo,
    data: Vec<u8>,
    hash: [u8; 32],
}

impl PriorityBundle {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl From<Transaction> for PriorityBundle {
    fn from(t: Transaction) -> Self {
        Self {
            epoch: t.nonce.to_epoch(),
            seqno: t.nonce.to_seqno(),
            data: t.data,
            hash: t.hash,
        }
    }
}

impl Committable for PriorityBundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("PriorityBundle")
            .field("epoch", self.epoch.commit())
            .field("seqno", self.seqno.commit())
            .var_size_field("data", &self.data)
            .finalize()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionSet {
    items: BTreeSet<Transaction>,
}

impl TransactionSet {
    pub fn new() -> Self {
        Self {
            items: BTreeSet::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn insert(&mut self, t: Transaction) {
        self.items.insert(t);
    }

    pub fn remove(&mut self, t: &Transaction) {
        self.items.remove(t);
    }

    pub fn contains(&self, t: &Transaction) -> bool {
        self.items.contains(t)
    }

    pub fn into_transactions(self) -> impl Iterator<Item = Transaction> {
        self.items.into_iter()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.items.iter()
    }
}

impl FromIterator<Transaction> for TransactionSet {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Transaction>,
    {
        Self {
            items: iter.into_iter().collect(),
        }
    }
}
