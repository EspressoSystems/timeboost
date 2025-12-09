use metrics::{Gauge, Metrics, NoMetrics};
use sailfish::types::RoundNumber;

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
            rbc_leader_info: m.create_gauge("rbc_leader_info_duration", Some("ms")),
            sf_delivery: m.create_gauge("sf_delivery_duration", Some("ms")),
            tb_decrypt: m.create_gauge("tb_decrypt_duration", Some("ms")),
            tb_certify: m.create_gauge("tb_certify_duration", Some("ms")),
            total: m.create_gauge("total_duration", Some("ms")),
        }
    }

    #[cfg(not(feature = "times"))]
    pub fn update(&self, _: RoundNumber) {}

    #[cfg(feature = "times")]
    pub fn update(&self, r: RoundNumber) {
        self.update_sf_round_duration(r);
        self.update_rbc_leader_info_duration(r);
        self.update_sf_delivery_duration(r);
        self.update_tb_decrypt_duration(r);
        self.update_tb_certify_duration(r);
        self.update_total_duration(r);
    }

    #[cfg(feature = "times")]
    fn update_sf_round_duration(&self, r: RoundNumber) {
        use sailfish::consensus::time_series::ROUND_START;

        let Some(a) = times::get(ROUND_START, r.saturating_sub(1)) else {
            return;
        };
        let Some(b) = times::get(ROUND_START, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.sf_round_duration.set(d.as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_rbc_leader_info_duration(&self, r: RoundNumber) {
        use sailfish::{
            consensus::time_series::ROUND_START, rbc::abraham::time_series::LEADER_INFO,
        };

        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(LEADER_INFO, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.rbc_leader_info.set(d.as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_sf_delivery_duration(&self, r: RoundNumber) {
        use sailfish::consensus::time_series::{DELIVERED, ROUND_START};

        let Some(a) = times::get(ROUND_START, r) else {
            return;
        };
        let Some(b) = times::get(DELIVERED, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.sf_delivery.set(d.as_millis() as usize)
    }

    #[cfg(feature = "times")]
    fn update_tb_decrypt_duration(&self, r: RoundNumber) {
        use timeboost_sequencer::time_series::{DECRYPT_END, DECRYPT_START};

        let Some(a) = times::get(DECRYPT_START, r) else {
            return;
        };
        let Some(b) = times::get(DECRYPT_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.tb_decrypt.set(d.as_millis() as usize)
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
        self.tb_decrypt.set(d.as_millis() as usize);
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
        self.tb_decrypt.set(d.as_millis() as usize);
    }
}
