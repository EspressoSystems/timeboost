use std::ops::Deref;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

const EPOCH_DURATION: Duration = Duration::from_secs(60);

/// Epoch number.
//
// TODO: Is a `u128` required here?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct Epoch(u128);

/// Unix timestamp in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
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
