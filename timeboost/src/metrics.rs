use metrics::{Counter, Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub epoch: Box<dyn Gauge>,
    pub epoch_duration: Box<dyn Histogram>,
    pub failed_epochs: Box<dyn Counter>,
}

impl Default for TimeboostMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl TimeboostMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            epoch: m.create_gauge("epoch", None),
            epoch_duration: m.create_histogram("epoch_duration", None, None),
            failed_epochs: m.create_counter("failed_epochs", None),
        }
    }
}
