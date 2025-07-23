use metrics::{Gauge, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct BuilderMetrics {
    pub block_submit: Box<dyn Gauge>,
    pub submit_tasks: Box<dyn Gauge>,
}

impl Default for BuilderMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl BuilderMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            block_submit: m.create_gauge("block_submit", None),
            submit_tasks: m.create_gauge("submit_tasks", None),
        }
    }
}
