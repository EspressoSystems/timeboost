use std::ops::{Add, Deref, Div};
use std::time::SystemTime;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

/// Class of types that can provide a timestamp.
pub trait HasTime {
    fn time(&self) -> Timestamp;
}

/// Unix timestamp in seconds.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Timestamp(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ConsensusTime(pub Timestamp);

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time >= unix epoch");
        Self(d.as_secs())
    }
}

impl Add<u64> for Timestamp {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Div<u64> for Timestamp {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
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

impl Deref for Timestamp {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for ConsensusTime {
    type Target = Timestamp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for Timestamp {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Timestamp")
            .u64(self.0)
            .finalize()
    }
}

impl HasTime for Timestamp {
    fn time(&self) -> Self {
        *self
    }
}
