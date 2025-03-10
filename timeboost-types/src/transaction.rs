use std::cmp::max;
use std::fmt;
use std::ops::Deref;

use alloy_primitives::{TxHash, U256};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use timeboost_crypto::KeysetId;

use crate::{Address, Bytes, Epoch, SeqNo};

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

impl From<(Epoch, SeqNo)> for Nonce {
    fn from((e, s): (Epoch, SeqNo)) -> Self {
        let mut n = Self(U256::ZERO);
        n.0 |= U256::from(u64::from(e)) << 128;
        n.0 |= U256::from(u64::from(s));
        n
    }
}

impl Committable for Nonce {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Nonce")
            .var_size_bytes(self.0.as_le_slice())
            .finalize()
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
pub struct Transaction {
    nonce: Nonce,
    to: Address,
    from: Address,
    data: Bytes,
    hash: Hash,
    kid: KeysetId,
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidTransaction> {
        <Self as Decodable>::decode(&mut &*bytes).map_err(InvalidTransaction)
    }

    pub fn new(nonce: Nonce, to: Address, from: Address, data: Bytes, kid: KeysetId) -> Self {
        let mut this = Self {
            nonce,
            to,
            from,
            data,
            hash: [0; 32].into(),
            kid,
        };
        this.update_hash();
        this
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

    pub fn encrypted(&self) -> bool {
        self.kid != KeysetId::from(0u64)
    }

    pub fn kid(&self) -> KeysetId {
        self.kid
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn digest(&self) -> &Hash {
        &self.hash
    }

    pub fn set_keyset(&mut self, kid: KeysetId) {
        self.kid = kid;
        self.update_hash()
    }

    pub fn set_data(&mut self, d: Bytes) {
        self.data = d;
        self.update_hash()
    }

    fn update_hash(&mut self) {
        use sha3::Digest;

        let mut h = sha3::Keccak256::new();
        h.update(self.to);
        h.update(self.from);
        h.update(self.nonce.0.as_le_slice());
        h.update(&self.data);
        h.update(&u64::from(self.kid).to_be_bytes()[..]);

        self.hash = <[u8; 32]>::from(h.finalize()).into();
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{to := {}, from := {}, nonce := {}, hash := {}}}",
            self.to, self.from, self.nonce, self.hash
        )
    }
}

impl Committable for Transaction {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Transaction")
            .field("to", self.to().commit())
            .field("from", self.from().commit())
            .field("nonce", self.nonce().commit())
            .u64_field("kid", self.kid.into())
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

        let mut data = vec![0; 8];
        data.extend_from_slice(&<Vec<u8>>::arbitrary(u)?);

        let mut this = Self {
            to: to.into(),
            from: from.into(),
            nonce: Nonce(U256::arbitrary(u)?),
            data: data.into(),
            hash: Hash::from([0; 32]),
            kid: KeysetId::from(0),
        };

        this.data.truncate(max(8, max_data));
        this.update_hash();

        Ok(this)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PriorityBundle(Transaction);

impl Deref for PriorityBundle {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Transaction> for PriorityBundle {
    fn from(t: Transaction) -> Self {
        Self(t)
    }
}

impl Committable for PriorityBundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("PriorityBundle")
            .field("transaction", self.0.commit())
            .finalize()
    }
}

#[cfg(feature = "arbitrary")]
impl PriorityBundle {
    pub fn arbitrary(
        to: Address,
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

        t.to = to;
        t.nonce = Nonce(nonce);
        t.update_hash();

        Ok(t)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("rlp error: {0}")]
pub struct InvalidTransaction(#[from] alloy_rlp::Error);

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use quickcheck::quickcheck;

    use super::Nonce;
    use crate::{Epoch, SeqNo};

    quickcheck! {
        fn epoch_seqno_nonce_identity(e: u64, s: u64) -> bool {
            let e = Epoch::from(e);
            let s = SeqNo::from(s);

            let n = Nonce::from((e, s));

            n.to_epoch() == e && n.to_seqno() == s
        }

        fn epoch_seqno_nonce_be_bytes_identity(e: u64, s: u64) -> bool {
            let e = Epoch::from(e);
            let s = SeqNo::from(s);

            let mut bytes = [0; 32];
            bytes[8  .. 16].copy_from_slice(&e.to_be_bytes()[..]);
            bytes[24 .. 32].copy_from_slice(&s.to_be_bytes()[..]);

            let n = Nonce(U256::from_be_bytes(bytes));

            n.to_epoch() == e && n.to_seqno() == s
        }
    }
}
