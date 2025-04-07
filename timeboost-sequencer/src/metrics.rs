use metrics::{Gauge, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct SequencerMetrics {
    /// Sailfish round number.
    pub sailfish_round: Box<dyn Gauge>,
    /// Timeboost round number.
    pub timeboost_round: Box<dyn Gauge>,
    /// Unix time.
    pub time: Box<dyn Gauge>,
    /// Number of Sailfish actions.
    pub sailfish_actions: Box<dyn Gauge>,
    /// Number of priority bundles in queue.
    pub queued_priority: Box<dyn Gauge>,
    /// Number of regular bundles in queue.
    pub queued_regular: Box<dyn Gauge>,
}

impl Default for SequencerMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl SequencerMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            sailfish_round: m.create_gauge("sailfish_round", None),
            timeboost_round: m.create_gauge("timeboost_round", None),
            time: m.create_gauge("sequencer_time", Some("s")),
            sailfish_actions: m.create_gauge("sailfish_actions", None),
            queued_priority: m.create_gauge("queued_prio_bundles", None),
            queued_regular: m.create_gauge("queued_reg_bundles", None),
        }
    }
}
