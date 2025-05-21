use std::ops::{Add, Deref};
use std::time::Duration;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

pub use sailfish_types::Timestamp;

const EPOCH_DURATION: Duration = Duration::from_secs(60);

/// Epoch number.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    pub fn now() -> Self {
        Timestamp::now().into()
    }
}

impl Add<u64> for Epoch {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Committable for Epoch {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Epoch").u64(self.0).finalize()
    }
}

impl From<Timestamp> for Epoch {
    fn from(t: Timestamp) -> Self {
        Epoch(*t / EPOCH_DURATION.as_secs())
    }
}

impl From<u64> for Epoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Epoch> for u64 {
    fn from(value: Epoch) -> Self {
        value.0
    }
}

impl Deref for Epoch {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Epoch, Timestamp};
    use quickcheck::quickcheck;

    quickcheck! {
        fn timestamp_of_epoch(n: u32) -> bool {
            let e: u64 = Epoch::from(Timestamp::from(u64::from(n))).into();
            let t: u64 = n.into();
            e * 60 <= t && t <= e * 60 + 59
        }
    }
}
