use std::ops::Deref;
use std::time::{Duration, SystemTime};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

pub const EPOCH_DURATION: Duration = Duration::from_secs(60);

/// Epoch number.
//
// TODO: Is a `u128` required here?
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Epoch(u128);

impl Epoch {
    pub fn new(value: u128) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unix timestamp in seconds.
#[derive(
    Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time >= unix epoch");
        Self(d.as_secs())
    }

    pub fn into_epoch(self) -> Epoch {
        Epoch(u128::from(self.0 / EPOCH_DURATION.as_secs()))
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl Committable for Timestamp {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Timestamp")
            .u64_field("timestamp", self.0)
            .finalize()
    }
}

pub fn median(ts: &mut [Timestamp]) -> Option<Timestamp> {
    if ts.is_empty() {
        return None;
    }
    ts.sort();
    if ts.len() % 2 == 0 {
        let a = ts[ts.len() / 2 - 1];
        let b = ts[ts.len() / 2];
        Some(Timestamp((*a + *b) / 2))
    } else {
        Some(ts[ts.len() / 2])
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
            let e: u128 = Timestamp(n).into_epoch().into();
            let t: u128 = n.into();
            e * 60 <= t && t <= e * 60 + 59
        }
    }

    #[test]
    fn median() {
        use super::median;

        let mut ts = [];
        assert_eq!(None, median(&mut ts));

        let mut ts = [1.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts));

        let mut ts = [1.into(), 2.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into(), 4.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into(), 4.into(), 5.into()];
        assert_eq!(Some(Timestamp::from(3)), median(&mut ts));
    }
}
