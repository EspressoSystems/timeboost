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
}

impl Transaction {
    pub fn new(nonce: Nonce, to: Address, data: Vec<u8>) -> Self {
        Self { nonce, to, data }
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PriorityBundle {
    epoch: Epoch,
    seqno: SeqNo,
    data: Vec<u8>,
    hash: blake3::Hash,
}

impl PriorityBundle {
    pub fn new(e: Epoch, s: SeqNo, d: Vec<u8>) -> Self {
        let h = blake3::hash(&d);
        Self {
            epoch: e,
            seqno: s,
            data: d,
            hash: h,
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    pub fn digest(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
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
