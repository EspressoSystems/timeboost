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
    pub queued_bundles: Box<dyn Gauge>,
    /// Number of transactions in queue.
    pub queued_transactions: Box<dyn Gauge>,
    /// Number of priority bundles in the inclusion list of `round`.
    pub included_bundles: Box<dyn Gauge>,
    /// Number of transactions in the inclusion list of `round`.
    pub included_transactions: Box<dyn Gauge>,
    /// Number of priority bundles in `round` that need to be retried.
    pub retry_bundles: Box<dyn Gauge>,
    /// Number of transactions in `round` that need to be retried.
    pub retry_transactions: Box<dyn Gauge>,
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
            round: m.create_gauge("round", None),
            time: m.create_gauge("time", Some("s")),
            queued_bundles: m.create_gauge("queued_bundles", None),
            queued_transactions: m.create_gauge("queued_transactions", None),
            included_bundles: m.create_gauge("included_bundles", None),
            included_transactions: m.create_gauge("included_transactions", None),
            retry_bundles: m.create_gauge("retry_bundles", None),
            retry_transactions: m.create_gauge("retry_transactions", None),
        }
    }
}
