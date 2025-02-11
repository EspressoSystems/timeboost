use timeboost_utils::traits::metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct ConsensusMetrics {
    pub committed_round: Box<dyn Gauge>,
    pub dag_depth: Box<dyn Gauge>,
    pub delivered: Box<dyn Gauge>,
    pub no_votes: Box<dyn Gauge>,
    pub round: Box<dyn Gauge>,
    pub round_duration: Box<dyn Histogram>,
    pub timeout_buffer: Box<dyn Gauge>,
    pub vertex_buffer: Box<dyn Gauge>,
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
            no_votes: m.create_gauge("no_votes", None),
            round: m.create_gauge("round", None),
            round_duration: m.create_histogram("round_duration", Some("seconds")),
            timeout_buffer: m.create_gauge("timeout_buffer", None),
            vertex_buffer: m.create_gauge("vertex_buffer", None),
        }
    }
}
