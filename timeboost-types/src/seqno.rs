use std::ops::{Add, Deref};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

/// Sequence number.
#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SeqNo(u128);

impl SeqNo {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl Add<u64> for SeqNo {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + u128::from(rhs))
    }
}

impl From<u128> for SeqNo {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<SeqNo> for u128 {
    fn from(value: SeqNo) -> Self {
        value.0
    }
}

impl Deref for SeqNo {
    type Target = u128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for SeqNo {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("SeqNo")
            .fixed_size_bytes(&self.0.to_be_bytes())
            .finalize()
    }
}
