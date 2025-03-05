use std::fmt;
use std::ops::Deref;

use alloy_primitives::{Bytes, TxHash, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Address, Epoch, SeqNo};

#[cfg(feature = "arbitrary")]
use arbitrary::Unstructured;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    RlpDecodable,
    RlpEncodable,
)]
#[rlp(transparent)]
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

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    RlpDecodable,
    RlpEncodable,
)]
#[rlp(transparent)]
pub struct Nonce(U256);

impl Nonce {
    pub fn to_epoch(self) -> Epoch {
        let n: u128 = (self.0 >> 128u8).try_into().unwrap();
        Epoch::from(n as u64)
    }

    pub fn to_seqno(self) -> SeqNo {
        let n: u128 = (self.0 & U256::from(u128::MAX)).try_into().unwrap();
        SeqNo::from(n as u64)
    }
}

impl Committable for Nonce {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Nonce")
            .var_size_bytes(self.0.as_le_slice())
            .finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
pub struct Transaction {
    nonce: Nonce,
    to: Address,
    from: Address,
    data: Bytes,
    v: u64,
    r: U256,
    s: U256,
    hash: Hash,
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidTransaction> {
        <Self as Decodable>::decode(&mut &*bytes).map_err(InvalidTransaction)
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn from(&self) -> &Address {
        &self.from
    }

    pub fn to(&self) -> &Address {
        &self.to
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Bytes {
        self.data.clone()
    }

    pub fn digest(&self) -> &Hash {
        &self.hash
    }

    #[cfg(feature = "arbitrary")]
    fn update_hash(&mut self) {
        use sha3::Digest;

        let mut h = sha3::Keccak256::new();
        h.update(self.to);
        h.update(self.from);
        h.update(self.nonce.0.as_le_slice());
        h.update(&self.data);
        h.update(&self.v.to_le_bytes()[..]);
        h.update(self.r.as_le_slice());
        h.update(self.s.as_le_slice());

        self.hash = <[u8; 32]>::from(h.finalize()).into();
    }
}

impl Committable for Transaction {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Transaction")
            .field("to", self.to().commit())
            .field("from", self.from().commit())
            .field("nonce", self.nonce().commit())
            .var_size_field("data", self.data())
            .fixed_size_bytes(self.digest().as_ref())
            .finalize()
    }
}

#[cfg(feature = "arbitrary")]
impl Transaction {
    pub fn arbitrary(max_data: usize, u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        use arbitrary::Arbitrary;

        let mut from = [0; 20];
        u.fill_buffer(&mut from)?;

        let mut to = [0; 20];
        u.fill_buffer(&mut to)?;

        let mut this = Self {
            to: to.into(),
            from: from.into(),
            nonce: Nonce(U256::arbitrary(u)?),
            data: Bytes::arbitrary(u)?,
            v: u64::arbitrary(u)?,
            r: U256::arbitrary(u)?,
            s: U256::arbitrary(u)?,
            hash: Hash::from([0; 32]),
        };

        this.data.truncate(max_data);
        this.update_hash();

        Ok(this)
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

#[cfg(feature = "arbitrary")]
impl PriorityBundle {
    pub fn arbitrary(
        max_seqno: u64,
        max_data: usize,
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<Transaction> {
        use arbitrary::Arbitrary;

        let mut t = Transaction::arbitrary(max_data, u)?;

        let e = Epoch::now() + bool::arbitrary(u)? as u64;
        let s = SeqNo::from(u.int_in_range(0..=max_seqno)?);

        let mut nonce = U256::ZERO;
        nonce |= U256::from(u64::from(e)) << 128;
        nonce |= U256::from(u64::from(s));

        t.nonce = Nonce(nonce);
        t.update_hash();

        Ok(t)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("rlp error: {0}")]
pub struct InvalidTransaction(#[from] alloy_rlp::Error);
