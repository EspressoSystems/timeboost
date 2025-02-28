use std::ops::{Add, Deref, Div};
use std::time::{Duration, SystemTime};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

const EPOCH_DURATION: Duration = Duration::from_secs(60);

/// Epoch number.
//
// TODO: Is a `u128` required here?
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Epoch(u128);

impl Epoch {
    pub fn now() -> Self {
        Timestamp::now().epoch()
    }
}

impl Add<u64> for Epoch {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + u128::from(rhs))
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Committable for Epoch {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Epoch")
            .fixed_size_bytes(&self.0.to_be_bytes())
            .finalize()
    }
}

/// Unix timestamp in seconds.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time >= unix epoch");
        Self(d.as_secs())
    }

    pub fn epoch(self) -> Epoch {
        Epoch(u128::from(self.0 / EPOCH_DURATION.as_secs()))
    }
}

impl Add for Timestamp {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Div<u64> for Timestamp {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl From<u128> for Epoch {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Epoch> for u128 {
    fn from(value: Epoch) -> Self {
        value.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

impl Deref for Epoch {
    type Target = u128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Timestamp {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;
    use quickcheck::quickcheck;

    quickcheck! {
        fn timestamp_of_epoch(n: u64) -> bool {
            let e: u128 = Timestamp(n).epoch().into();
            let t: u128 = n.into();
            e * 60 <= t && t <= e * 60 + 59
        }
    }
}
