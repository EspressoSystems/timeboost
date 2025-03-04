use std::fmt;
use std::ops::Deref;

use alloy_consensus::transaction::PooledTransaction;
use alloy_consensus::Transaction as _;
use alloy_primitives::{Bytes, TxHash};
use alloy_rlp::{Decodable, Encodable};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{Address, Epoch, SeqNo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(TxHash);

impl From<[u8; 32]> for Hash {
    fn from(value: [u8; 32]) -> Self {
        Hash(value.into())
    }
}

impl AsRef<[u8; 32]> for Hash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl Deref for Hash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce(u64);

impl Nonce {
    pub fn to_epoch(self) -> Epoch {
        Epoch::from(self.0 >> 32)
    }

    pub fn to_seqno(self) -> SeqNo {
        SeqNo::from(0x0000_0000_FFFF_FFFF & self.0)
    }
}

impl From<u64> for Nonce {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<Nonce> for u64 {
    fn from(val: Nonce) -> Self {
        val.0
    }
}

impl Committable for Nonce {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Nonce").u64(self.0).finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction {
    hash: Hash,
    tx: PooledTransaction,
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidTransaction> {
        let tx = PooledTransaction::decode(&mut &*bytes)?;
        Ok(Self {
            hash: Hash(*tx.hash()),
            tx,
        })
    }

    pub fn nonce(&self) -> Nonce {
        self.tx.nonce().into()
    }

    pub fn from(&self) -> Option<Address> {
        self.tx.recover_signer().ok().map(Address::from)
    }

    pub fn to(&self) -> Option<Address> {
        self.tx.to().map(Address::from)
    }

    pub fn data(&self) -> &[u8] {
        self.tx.input()
    }

    pub fn into_data(self) -> Bytes {
        self.tx.input().clone()
    }

    pub fn digest(&self) -> &Hash {
        &self.hash
    }
}

impl Committable for Transaction {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Transaction")
            .optional("to", &self.to())
            .optional("from", &self.from())
            .field("nonce", self.nonce().commit())
            .var_size_field("data", self.data())
            .fixed_size_bytes(self.digest().as_ref())
            .finalize()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Transaction {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let tx = PooledTransaction::arbitrary(u)?;
        Ok(Self {
            hash: Hash(*tx.hash()),
            tx,
        })
    }
}

impl Serialize for Transaction {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::new();
        self.tx.encode(&mut buf);
        s.serialize_bytes(&buf)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let buf = <Vec<u8>>::deserialize(d)?;
        Self::decode(&buf).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PriorityBundle {
    epoch: Epoch,
    seqno: SeqNo,
    hash: Hash,
    data: Bytes,
}

impl PriorityBundle {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    pub fn digest(&self) -> &Hash {
        &self.hash
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Bytes {
        self.data
    }
}

impl From<Transaction> for PriorityBundle {
    fn from(t: Transaction) -> Self {
        Self {
            epoch: t.nonce().to_epoch(),
            seqno: t.nonce().to_seqno(),
            hash: *t.digest(),
            data: t.into_data(),
        }
    }
}

impl Committable for PriorityBundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("PriorityBundle")
            .field("epoch", self.epoch.commit())
            .field("seqno", self.seqno.commit())
            .fixed_size_field("hash", self.hash.as_ref())
            .var_size_field("data", &self.data)
            .finalize()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("rlp error: {0}")]
pub struct InvalidTransaction(#[from] alloy_rlp::Error);
