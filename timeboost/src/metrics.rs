#[cfg(feature = "times")]
use std::time::Instant;

use metrics::{Gauge, Metrics, NoMetrics};
use sailfish::types::RoundNumber;

#[cfg(feature = "times")]
use times::TimeSeries;

#[derive(Debug)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub sf_round_duration: Box<dyn Gauge>,
    pub rbc_leader_info: Box<dyn Gauge>,
    pub sf_delivery: Box<dyn Gauge>,
    pub tb_decrypt: Box<dyn Gauge>,
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
            sf_round_duration: m.create_gauge("sf_round_duration", Some("ms")),
            rbc_leader_info: m.create_gauge("rbc_leader_info", Some("ms")),
            sf_delivery: m.create_gauge("sf_delivery", Some("ms")),
            tb_decrypt: m.create_gauge("tb_decrypt", Some("ms")),
            tb_certify: m.create_gauge("tb_certify", Some("ms")),
            total: m.create_gauge("total_duration", Some("ms")),
        }
    }

    #[cfg(not(feature = "times"))]
    pub fn update(&self, _: RoundNumber) {}

    #[cfg(feature = "times")]
    pub fn update(&self, r: RoundNumber) {
        use sailfish::consensus::time_series::ROUND_START;

        if let Some(ts) = times::time_series(ROUND_START) {
            self.update_sf_round_duration(r, &ts);
            self.update_rbc_leader_info(r, &ts);
            self.update_sf_delivery(r, &ts);
        }

        self.update_tb_decrypt(r);
        self.update_tb_certify(r);
    }

    #[cfg(feature = "times")]
    fn update_sf_round_duration(&self, r: RoundNumber, ts: &TimeSeries) {
        let Some(a) = ts.records().get(&r.saturating_sub(1)) else {
            return;
        };
        let Some(b) = ts.records().get(&*r) else {
            return;
        };
        self.sf_round_duration
            .set(b.saturating_duration_since(*a).as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_rbc_leader_info(&self, r: RoundNumber, ts: &TimeSeries) {
        use sailfish::rbc::abraham::time_series::LEADER_INFO;

        let Some(a) = ts.records().get(&*r) else {
            return;
        };
        let Some(b) = lookup(LEADER_INFO, r) else {
            return;
        };
        self.rbc_leader_info
            .set(b.saturating_duration_since(*a).as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_sf_delivery(&self, r: RoundNumber, ts: &TimeSeries) {
        use sailfish::consensus::time_series::DELIVERED;

        let Some(a) = ts.records().get(&*r) else {
            return;
        };
        let Some(b) = lookup(DELIVERED, r) else {
            return;
        };
        self.sf_delivery
            .set(b.saturating_duration_since(*a).as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_tb_decrypt(&self, r: RoundNumber) {
        use timeboost_sequencer::time_series::{DECRYPT_END, DECRYPT_START};

        let Some(a) = lookup(DECRYPT_START, r) else {
            return;
        };
        let Some(b) = lookup(DECRYPT_END, r) else {
            return;
        };
        self.tb_decrypt
            .set(b.saturating_duration_since(a).as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_tb_certify(&self, r: RoundNumber) {
        use timeboost_builder::time_series::{CERTIFY_END, CERTIFY_START};

        let Some(a) = lookup(CERTIFY_START, r) else {
            return;
        };
        let Some(b) = lookup(CERTIFY_END, r) else {
            return;
        };
        self.tb_decrypt
            .set(b.saturating_duration_since(a).as_millis() as usize);
    }
}

#[cfg(feature = "times")]
fn lookup(name: &str, r: RoundNumber) -> Option<Instant> {
    let ts = times::time_series(name)?;
    ts.records().get(&*r).copied()
}
