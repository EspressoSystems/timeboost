use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// An unspecified epoch for use with `Timestamp`.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Time measured as duration in µs since an unspecified epoch.
#[derive(Debug, Copy, Clone)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn now() -> Self {
        Self(Instant::now().saturating_duration_since(*EPOCH).as_micros() as u64)
    }

    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    pub fn try_from_slice(b: &[u8]) -> Option<Self> {
        let bytes = b.try_into().ok()?;
        Some(Self::from_bytes(bytes))
    }

    pub fn diff(self, other: Self) -> Option<Duration> {
        self.0.checked_sub(other.0).map(Duration::from_micros)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn duration() {
        let d = Duration::from_millis(50);
        let a = Timestamp::now();
        sleep(d).await;
        let b = Timestamp::now();
        let x = b.diff(a).unwrap();
        assert!(x - d < Duration::from_millis(5))
    }
}
