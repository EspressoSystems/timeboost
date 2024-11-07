use hotshot_types::traits::metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct ConsensusMetrics {
    pub round: Box<dyn Gauge>,
    pub round_duration: Box<dyn Histogram>,
    pub no_votes: Box<dyn Gauge>,
    pub dag_depth: Box<dyn Gauge>,
    pub vertex_buffer: Box<dyn Gauge>,
}

impl Default for ConsensusMetrics {
    fn default() -> Self {
        Self::new(NoMetrics)
    }
}

impl ConsensusMetrics {
    pub fn new<M: Metrics>(m: M) -> Self {
        Self {
            round: m.create_gauge("round".to_string(), None),
            round_duration: m
                .create_histogram("round-duration".to_string(), Some("seconds".to_string())),
            no_votes: m.create_gauge("no-votes".to_string(), None),
            dag_depth: m.create_gauge("dag-depth".to_string(), None),
            vertex_buffer: m.create_gauge("vertex-buffer".to_string(), None),
        }
    }
}
