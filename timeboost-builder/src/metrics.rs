use metrics::{Counter, Metrics, NoMetrics};

#[derive(Debug)]
#[non_exhaustive]
pub struct BuilderMetrics {
    pub blocks_submitted: Box<dyn Counter>,
    pub blocks_verified: Box<dyn Counter>,
}

impl Default for BuilderMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl BuilderMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            blocks_submitted: m.create_counter("blocks_submitted", None),
            blocks_verified: m.create_counter("blocks_verified", None),
        }
    }
}
