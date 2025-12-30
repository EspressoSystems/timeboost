use prometheus::{IntGauge, Result, register_int_gauge};
use sailfish::types::RoundNumber;
use sailfish::types::time_series::ROUND_START;
use timeboost_builder::time_series::{CERTIFY_END, CERTIFY_START};

#[derive(Debug)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub tb_certify: IntGauge,
    pub total: IntGauge,
}

impl TimeboostMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            tb_certify: register_int_gauge! {
                "tb_certify_duration_ms",
                "certify duration (certify_end(r) - certify_start(r))"
            }?,
            total: register_int_gauge! {
                "total_duration_ms",
                "round duration (certify_end(r)) - start(r))"
            }?,
        })
    }

    pub fn update(&self, r: RoundNumber) {
        self.update_tb_certify_duration(r);
        self.update_total_duration(r);
    }

    fn update_tb_certify_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(CERTIFY_START, r) else {
            return;
        };
        let Some(b) = times::get(CERTIFY_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.tb_certify.set(d.as_millis() as i64);
    }

    fn update_total_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(CERTIFY_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.total.set(d.as_millis() as i64);
    }
}
