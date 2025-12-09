use metrics::{Gauge, Metrics, NoMetrics};
use sailfish::types::RoundNumber;

#[derive(Debug)]
#[allow(unused)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub tb_certify: Box<dyn Gauge>,
    pub total: Box<dyn Gauge>,
}

impl Default for TimeboostMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl TimeboostMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            tb_certify: m.create_gauge("tb_certify_duration", Some("ms")),
            total: m.create_gauge("total_duration", Some("ms")),
        }
    }

    #[cfg(not(feature = "times"))]
    pub fn update(&self, _: RoundNumber) {}

    #[cfg(feature = "times")]
    pub fn update(&self, r: RoundNumber) {
        self.update_tb_certify_duration(r);
        self.update_total_duration(r);
    }

    #[cfg(feature = "times")]
    fn update_tb_certify_duration(&self, r: RoundNumber) {
        use timeboost_builder::time_series::{CERTIFY_END, CERTIFY_START};

        let Some(a) = times::get(CERTIFY_START, r) else {
            return;
        };
        let Some(b) = times::get(CERTIFY_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.tb_certify.set(d.as_millis() as usize);
    }

    #[cfg(feature = "times")]
    fn update_total_duration(&self, r: RoundNumber) {
        use sailfish::consensus::time_series::ROUND_START;
        use timeboost_builder::time_series::CERTIFY_END;

        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(CERTIFY_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.total.set(d.as_millis() as usize);
    }
}
