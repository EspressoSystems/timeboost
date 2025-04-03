use metrics::{Gauge, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct SequencerMetrics {
    /// Unix time.
    pub time: Box<dyn Gauge>,
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
            time: m.create_gauge("sequencer_time", Some("s")),
            queued_priority: m.create_gauge("queued_prio_bundles", None),
            queued_regular: m.create_gauge("queued_reg_bundles", None),
        }
    }
}
