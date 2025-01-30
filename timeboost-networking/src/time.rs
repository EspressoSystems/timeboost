use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Unix timestamp.
#[derive(Debug, Copy, Clone)]
pub struct Timestamp(Duration);

impl Timestamp {
    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(now)
    }

    pub fn try_from_slice(b: &[u8]) -> Option<Self> {
        let us = u64::from_be_bytes(b.try_into().ok()?);
        Some(Self(Duration::from_micros(us)))
    }

    pub fn to_bytes(self) -> [u8; 8] {
        (self.0.as_micros() as u64).to_be_bytes()
    }

    pub fn diff(self, other: Self) -> Option<Duration> {
        self.0.checked_sub(other.0)
    }
}
