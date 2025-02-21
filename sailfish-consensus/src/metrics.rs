use metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct ConsensusMetrics {
    pub committed_round: Box<dyn Gauge>,
    pub dag_depth: Box<dyn Gauge>,
    pub delivered: Box<dyn Gauge>,
    pub round: Box<dyn Gauge>,
    pub round_duration: Box<dyn Histogram>,
    pub timeout_buffer: Box<dyn Gauge>,
    pub novote_buffer: Box<dyn Gauge>,
    pub rounds_buffer: Box<dyn Gauge>,
    pub vertex_buffer: Box<dyn Gauge>,
    pub rounds_timed_out: Box<dyn Gauge>,
}

impl Default for ConsensusMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl ConsensusMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            committed_round: m.create_gauge("committed_round", None),
            dag_depth: m.create_gauge("dag_depth", None),
            delivered: m.create_gauge("delivered_filter", None),
            round: m.create_gauge("round", None),
            round_duration: m.create_histogram("round_duration", Some("seconds")),
            timeout_buffer: m.create_gauge("timeout_buffer", None),
            novote_buffer: m.create_gauge("novote_buffer", None),
            rounds_buffer: m.create_gauge("rounds_buffer", None),
            vertex_buffer: m.create_gauge("vertex_buffer", None),
            rounds_timed_out: m.create_gauge("rounds_timed_out", None),
        }
    }
}
