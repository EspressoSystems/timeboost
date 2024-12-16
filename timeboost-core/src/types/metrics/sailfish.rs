use timeboost_utils::traits::metrics::{Counter, Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct SailfishMetrics {
    pub committed_round: Box<dyn Gauge>,
    pub dag_depth: Box<dyn Gauge>,
    pub delivered: Box<dyn Gauge>,
    pub round: Box<dyn Gauge>,
    pub round_duration: Box<dyn Histogram>,
    pub timeout_buffer: Box<dyn Gauge>,
    pub novote_buffer: Box<dyn Gauge>,
    pub rounds_buffer: Box<dyn Gauge>,
    pub vertex_buffer: Box<dyn Gauge>,
    pub average_tx_size: Box<dyn Histogram>,
    pub tx_processed: Box<dyn Counter>,
    pub rounds_timed_out: Box<dyn Gauge>,
}

impl Default for SailfishMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl SailfishMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            committed_round: m.create_gauge("committed_round".to_string(), None),
            dag_depth: m.create_gauge("dag_depth".to_string(), None),
            delivered: m.create_gauge("delivered_filter".to_string(), None),
            round: m.create_gauge("round".to_string(), None),
            round_duration: m
                .create_histogram("round_duration".to_string(), Some("seconds".to_string())),
            timeout_buffer: m.create_gauge("timeout_buffer".to_string(), None),
            novote_buffer: m.create_gauge("novote_buffer".to_string(), None),
            rounds_buffer: m.create_gauge("rounds_buffer".to_string(), None),
            vertex_buffer: m.create_gauge("vertex_buffer".to_string(), None),
            average_tx_size: m
                .create_histogram("average_tx_size".to_string(), Some("bytes".to_string())),
            tx_processed: m.create_counter("transactions_processed".to_string(), None),
            rounds_timed_out: m.create_gauge("rounds_timed_out".to_string(), None),
        }
    }
}
