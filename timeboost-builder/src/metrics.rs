use metrics::{Counter, Gauge, Metrics, NoMetrics};

#[cfg(feature = "times")]
use timeboost_types::sailfish::RoundNumber;

#[derive(Debug)]
#[allow(unused)]
#[non_exhaustive]
pub struct BuilderMetrics {
    pub blocks_submitted: Box<dyn Counter>,
    pub blocks_verified: Box<dyn Counter>,
    pub verified: Box<dyn Gauge>,
}

impl Default for BuilderMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl BuilderMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            blocks_submitted: m.create_counter("blocks_submitted", None),
            blocks_verified: m.create_counter("blocks_verified", None),
            verified: m.create_gauge("verified_duration", Some("ms")),
        }
    }

    #[cfg(feature = "times")]
    pub fn update_verified_duration(&self, r: RoundNumber) {
        use crate::time_series::VERIFIED;
        use timeboost_types::sailfish::time_series::ROUND_START;

        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(VERIFIED, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.verified.set(d.as_millis() as usize);
    }
}
