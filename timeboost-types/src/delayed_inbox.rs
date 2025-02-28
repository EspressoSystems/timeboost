use std::ops::{Add, Div};

use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct DelayedInboxIndex(u64);

impl Add for DelayedInboxIndex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Div<u64> for DelayedInboxIndex {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl From<u64> for DelayedInboxIndex {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<DelayedInboxIndex> for u64 {
    fn from(val: DelayedInboxIndex) -> Self {
        val.0
    }
}
