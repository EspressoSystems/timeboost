use metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct SequencerMetrics {
    /// Decryption phase duration.
    pub decrypt_duration: Box<dyn Histogram>,
    /// Round number.
    pub round: Box<dyn Gauge>,
    /// Unix time.
    pub time: Box<dyn Gauge>,
    /// Number of priority bundles in queue.
    pub queued_priority: Box<dyn Gauge>,
    /// Number of regular bundles in queue.
    pub queued_regular: Box<dyn Gauge>,
    /// Number of priority bundles in the inclusion list of `round`.
    pub included_priority: Box<dyn Gauge>,
    /// Number of regular bundles in the inclusion list of `round`.
    pub included_regular: Box<dyn Gauge>,
    /// Number of priority bundles in `round` that need to be retried.
    pub retry_priority: Box<dyn Gauge>,
    /// Number of regular bundles in `round` that need to be retried.
    pub retry_regular: Box<dyn Gauge>,
}

impl Default for SequencerMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl SequencerMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        let buckets = &[
            0.01, 0.05, 0.1, 0.2, 0.5, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 75.0, 100.0, 150.0,
            200.0, 500.0,
        ];
        Self {
            decrypt_duration: m.create_histogram("decrypt_duration", Some("ms"), Some(buckets)),
            round: m.create_gauge("sequencer_round", None),
            time: m.create_gauge("sequencer_time", Some("s")),
            queued_priority: m.create_gauge("queued_prio_bundles", None),
            queued_regular: m.create_gauge("queued_reg_bundles", None),
            included_priority: m.create_gauge("included_prio_bundles", None),
            included_regular: m.create_gauge("included_reg_bundles", None),
            retry_priority: m.create_gauge("retry_prio_bundles", None),
            retry_regular: m.create_gauge("retry_reg_bundles", None),
        }
    }
}
