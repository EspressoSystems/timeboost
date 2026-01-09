use prometheus::{IntCounter, IntGauge, Result, register_int_counter, register_int_gauge};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BuilderMetrics {
    pub blocks_submitted: IntCounter,
    pub pending_blocks: IntGauge,
    pub inbound_blocks_cap: IntGauge,
}

impl BuilderMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            blocks_submitted: register_int_counter!(
                "blocks_submitted",
                "number of submitted blocks"
            )?,
            pending_blocks: register_int_gauge!(
                "pending_blocks",
                "number of pending blocks to submit"
            )?,
            inbound_blocks_cap: register_int_gauge!(
                "inbound_blocks_cap",
                "inbound blocks capacity"
            )?,
        })
    }
}
