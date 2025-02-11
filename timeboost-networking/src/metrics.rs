use timeboost_utils::traits::metrics::{Gauge, Histogram, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkMetrics {
    pub connections: Box<dyn Gauge>,
    pub latency: Box<dyn Histogram>,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl NetworkMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            latency: m.create_histogram("latency", Some("ms")),
            connections: m.create_gauge("connections", None),
        }
    }
}
