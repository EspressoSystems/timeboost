use std::num::{NonZeroUsize, ParseIntError};
use std::{fmt, str::FromStr};

use std::sync::Arc;

use bimap::BiBTreeMap;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::{KeyId, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committee {
    id: CommitteeId,
    parties: Arc<BiBTreeMap<KeyId, PublicKey>>,
}

impl Committee {
    pub fn new<C, I, T>(id: C, it: I) -> Self
    where
        C: Into<CommitteeId>,
        I: IntoIterator<Item = (T, PublicKey)>,
        T: Into<KeyId>,
    {
        let map = BiBTreeMap::from_iter(it.into_iter().map(|(i, k)| (i.into(), k)));
        assert!(!map.is_empty());
        Self {
            id: id.into(),
            parties: Arc::new(map),
        }
    }

    pub fn id(&self) -> CommitteeId {
        self.id
    }

    /// Returns the size of the committee as a non-zero unsigned integer.
    pub fn size(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.parties.len()).expect("committee is not empty")
    }

    /// Returns the at-least-one-honest threshold for consensus, which is `ceil(n/3)` where `n` is
    /// the committee size.
    pub fn one_honest_threshold(&self) -> NonZeroUsize {
        let t = self.parties.len().div_ceil(3);
        NonZeroUsize::new(t).expect("ceil(n/3) with n > 0 never gives 0")
    }

    /// Computes the quorum size
    pub fn quorum_size(&self) -> NonZeroUsize {
        let q = self.parties.len() * 2 / 3 + 1;
        NonZeroUsize::new(q).expect("n + 1 > 0")
    }

    /// Retrieves the public key associated with the given key ID.
    pub fn get_key<T: Into<KeyId>>(&self, ix: T) -> Option<&PublicKey> {
        self.parties.get_by_left(&ix.into())
    }

    /// Finds the key ID for a given public key.
    pub fn get_index(&self, k: &PublicKey) -> Option<KeyId> {
        self.parties.get_by_right(k).copied()
    }

    /// Checks if a public key is part of the committee.
    pub fn contains_key(&self, k: &PublicKey) -> bool {
        self.parties.contains_right(k)
    }

    /// Checks if a key ID is part of the committee.
    pub fn contains_index(&self, idx: &KeyId) -> bool {
        self.parties.contains_left(idx)
    }

    /// Returns an iterator over all entries in the committee.
    pub fn entries(&self) -> impl Iterator<Item = (KeyId, &PublicKey)> {
        self.parties.iter().map(|e| (*e.0, e.1))
    }

    /// Provides an iterator over all public keys in the committee.
    pub fn parties(&self) -> impl Iterator<Item = &PublicKey> {
        self.parties.right_values()
    }

    /// Determines the leader for a given round number using a round-robin method.
    pub fn leader(&self, round: usize) -> PublicKey {
        let i = round % self.parties.len();
        self.parties
            .right_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }

    /// Returns the key ID of the leader for a given round number.
    pub fn leader_index(&self, round: usize) -> KeyId {
        let i = round % self.parties.len();
        self.parties
            .left_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Encode, Decode,
)]
#[cbor(transparent)]
#[serde(transparent)]
pub struct CommitteeId(u64);

impl CommitteeId {
    pub const fn new(n: u64) -> Self {
        Self(n)
    }
}

impl From<u64> for CommitteeId {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<CommitteeId> for u64 {
    fn from(val: CommitteeId) -> Self {
        val.0
    }
}

impl fmt::Display for CommitteeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for CommitteeId {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.parse::<u64>()?;
        Ok(Self(v))
    }
}

impl Committable for CommitteeId {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CommitteeId")
            .u64(self.0)
            .finalize()
    }
}
