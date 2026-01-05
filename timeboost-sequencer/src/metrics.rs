use crate::time_series::{DECRYPT_END, DECRYPT_START};
use prometheus::{IntGauge, Result, register_int_gauge};
use sailfish::rbc::abraham::time_series::LEADER_INFO;
use sailfish::types::RoundNumber;
use sailfish::types::time_series::{DELIVERED, ROUND_START};

#[derive(Debug)]
#[non_exhaustive]
pub struct SequencerMetrics {
    /// Current committee id.
    pub committee: IntGauge,
    /// Sailfish round number duration.
    pub sf_round_duration: IntGauge,
    /// RBC leader info duration (relative to sailfish round start).
    pub rbc_leader_info: IntGauge,
    /// Sailfish delivery duration (relative to sailfish round start).
    pub sf_delivery: IntGauge,
    /// Timeboost decrypt duration.
    pub tb_decrypt: IntGauge,
}

impl SequencerMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            committee: register_int_gauge!("committee_id", "actual committee id")?,
            sf_round_duration: register_int_gauge!(
                "sf_round_duration_ms",
                "sailfish successive round delta (start(r + 1) - start(r))"
            )?,
            rbc_leader_info: register_int_gauge!(
                "rbc_leader_info_duration_ms",
                "rbc leader info (time(2f+1 messages of r+1) - start(r))"
            )?,
            sf_delivery: register_int_gauge!(
                "sf_delivery_duration_ms",
                "sailfish delivery duration (delivered(r) - start(r))"
            )?,
            tb_decrypt: register_int_gauge!(
                "tb_decrypt_duration_ms",
                "decrypt duration (decrypt_end(r) - decrypt_start(r))"
            )?,
        })
    }

    pub fn update(&self, r: RoundNumber) {
        self.update_sf_round_duration(r);
        self.update_rbc_leader_info_duration(r);
        self.update_sf_delivery_duration(r);
        self.update_tb_decrypt_duration(r);
    }

    fn update_sf_round_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(ROUND_START, r.saturating_sub(1)) else {
            return;
        };
        let Some(b) = times::get(ROUND_START, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.sf_round_duration.set(d.as_millis() as i64)
    }

    fn update_rbc_leader_info_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(LEADER_INFO, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.rbc_leader_info.set(d.as_millis() as i64)
    }

    fn update_sf_delivery_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(DELIVERED, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.sf_delivery.set(d.as_millis() as i64)
    }

    fn update_tb_decrypt_duration(&self, r: RoundNumber) {
        let Some(a) = times::get(DECRYPT_START, r) else {
            return;
        };
        let Some(b) = times::get(DECRYPT_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.tb_decrypt.set(d.as_millis() as i64)
    }
}
