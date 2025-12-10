use metrics::{Counter, Gauge, Metrics, NoMetrics};
use sailfish::types::RoundNumber;

#[derive(Debug)]
#[allow(unused)]
#[non_exhaustive]
pub struct SequencerMetrics {
    /// Unix time.
    pub time: Box<dyn Gauge>,
    /// Current committee id.
    pub committee: Box<dyn Gauge>,
    /// Number of priority bundles in queue.
    pub queued_priority: Box<dyn Gauge>,
    /// Number of regular bundles in queue.
    pub queued_regular: Box<dyn Gauge>,
    /// Number of encrypted inclusion list ever enqueued.
    pub queued_encrypted: Box<dyn Counter>,
    /// Number of decrypted inclusion list ever outputed (by Decrypter, may not
    /// by Sequencer yet).
    pub output_decrypted: Box<dyn Counter>,
    /// Sailfish round number duration.
    pub sf_round_duration: Box<dyn Gauge>,
    /// RBC leader info duration (relative to sailfish round start).
    pub rbc_leader_info: Box<dyn Gauge>,
    /// Sailfish delivery duration (relative to sailfish round start).
    pub sf_delivery: Box<dyn Gauge>,
    /// Timeboost decrypt duration.
    pub tb_decrypt: Box<dyn Gauge>,
}

impl Default for SequencerMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl SequencerMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        let m = Self {
            time: m.create_gauge("sequencer_time", Some("s")),
            committee: m.create_gauge("committee_id", None),
            queued_priority: m.create_gauge("queued_prio_bundles", None),
            queued_regular: m.create_gauge("queued_reg_bundles", None),
            queued_encrypted: m.create_counter("queued_encrypted_ilist", None),
            output_decrypted: m.create_counter("output_decrypted_ilist", None),
            sf_round_duration: m.create_gauge("sf_round_duration", Some("ms")),
            rbc_leader_info: m.create_gauge("rbc_leader_info_duration", Some("ms")),
            sf_delivery: m.create_gauge("sf_delivery_duration", Some("ms")),
            tb_decrypt: m.create_gauge("tb_decrypt_duration", Some("ms")),
        };
        m.committee.set(0);
        m
    }

    #[cfg(not(feature = "times"))]
    pub fn update(&self, _: RoundNumber) {}

    #[cfg(feature = "times")]
    pub fn update(&self, r: RoundNumber) {
        self.update_sf_round_duration(r);
        self.update_rbc_leader_info_duration(r);
        self.update_sf_delivery_duration(r);
        self.update_tb_decrypt_duration(r);
    }

    #[cfg(feature = "times")]
    fn update_sf_round_duration(&self, r: RoundNumber) {
        use sailfish::types::time_series::ROUND_START;

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
        use sailfish::{rbc::abraham::time_series::LEADER_INFO, types::time_series::ROUND_START};

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
        use sailfish::types::time_series::{DELIVERED, ROUND_START};

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
        use crate::time_series::{DECRYPT_END, DECRYPT_START};

        let Some(a) = times::get(DECRYPT_START, r) else {
            return;
        };
        let Some(b) = times::get(DECRYPT_END, r) else {
            return;
        };
        let d = b.saturating_duration_since(a);
        self.tb_decrypt.set(d.as_millis() as usize)
    }
}
