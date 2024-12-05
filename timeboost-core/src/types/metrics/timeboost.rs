use timeboost_utils::traits::metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub epoch: Box<dyn Gauge>,
    pub epoch_duration: Box<dyn Histogram>,
}

impl Default for TimeboostMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl TimeboostMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            epoch: m.create_gauge("epoch".to_string(), None),
            epoch_duration: m.create_histogram("epoch_duration".to_string(), None),
        }
    }
}
