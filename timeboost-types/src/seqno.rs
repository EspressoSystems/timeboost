use std::ops::{Add, Deref};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

/// Sequence number.
#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct SeqNo(u64);

impl SeqNo {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn as_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl Add<u64> for SeqNo {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl From<u64> for SeqNo {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SeqNo> for u64 {
    fn from(value: SeqNo) -> Self {
        value.0
    }
}

impl Deref for SeqNo {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for SeqNo {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("SeqNo").u64(self.0).finalize()
    }
}
