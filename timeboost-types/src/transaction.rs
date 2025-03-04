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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeysetId(u32);

impl From<u32> for KeysetId {
    fn from(value: u32) -> Self {
        KeysetId(value)
    }
}

impl From<&[u8]> for KeysetId {
    fn from(v: &[u8]) -> Self {
        Self(u32::from_be_bytes(
            v[0..4].try_into().expect("4 bytes is always u32"),
        ))
    }
}

impl KeysetId {
    pub fn parse_from(data: &[u8]) -> KeysetId {
        if data.len() >= 4 {
            return KeysetId::from(&data[..4]);
        }
        KeysetId(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Transaction {
    to: Address,
    nonce: Nonce,
    data: Vec<u8>,
    hash: [u8; 32],
    kid: KeysetId,
}

impl Transaction {
    pub fn new(nonce: Nonce, to: Address, data: Vec<u8>, kid: KeysetId) -> Self {
        let h = blake3::hash(&data);
        Self {
            nonce,
            to,
            data,
            hash: h.into(),
            kid,
        }
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    pub fn to(&self) -> Address {
        self.to
    }

    pub fn encrypted(&self) -> bool {
        self.kid != KeysetId(0)
    }

    pub fn kid(&self) -> KeysetId {
        self.kid
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

    pub fn set_keyset(&mut self, kid: KeysetId) {
        self.kid = kid
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
    kid: KeysetId,
}

impl PriorityBundle {
    pub fn new(epoch: Epoch, seqno: SeqNo, data: Vec<u8>, hash: [u8; 32], kid: KeysetId) -> Self {
        Self {
            epoch,
            seqno,
            data,
            hash,
            kid,
        }
    }

    pub fn new_compute_hash(epoch: Epoch, seqno: SeqNo, data: Vec<u8>, kid: KeysetId) -> Self {
        let h = blake3::hash(&data);
        Self::new(epoch, seqno, data, h.into(), kid)
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn encrypted(&self) -> bool {
        self.kid != KeysetId(0)
    }

    pub fn kid(&self) -> KeysetId {
        self.kid
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
            kid: KeysetId(0),
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
