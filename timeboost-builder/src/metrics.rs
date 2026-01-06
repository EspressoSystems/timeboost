use prometheus::{IntCounter, Result, register_int_counter};

#[derive(Debug)]
#[non_exhaustive]
pub struct BuilderMetrics {
    pub blocks_submitted: IntCounter,
}

impl BuilderMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            blocks_submitted: register_int_counter!(
                "blocks_submitted",
                "number of submitted blocks"
            )?,
        })
    }
}
