use prometheus::{IntCounter, IntGauge, register_int_counter, register_int_gauge};

#[derive(Debug)]
#[non_exhaustive]
pub struct ConsensusMetrics {
    pub committed_round: IntGauge,
    pub dag_depth: IntGauge,
    pub delivered: IntGauge,
    pub round: IntGauge,
    pub timeout_buffer: IntGauge,
    pub novote_buffer: IntGauge,
    pub rounds_buffer: IntGauge,
    pub vertex_buffer: IntGauge,
    pub rounds_timed_out: IntCounter,
}

impl ConsensusMetrics {
    pub fn new() -> prometheus::Result<Self> {
        Ok(Self {
            committed_round: register_int_gauge!("committed_round", "committed round number")?,
            dag_depth: register_int_gauge!("dag_depth", "number of rounds in a dag")?,
            round: register_int_gauge!("round", "current round number")?,
            delivered: register_int_gauge!("delivered_buffer", "size of delivered items buffer")?,
            timeout_buffer: register_int_gauge!("timeout_buffer", "size of timeout buffer")?,
            novote_buffer: register_int_gauge!("novote_buffer", "size of no-vote buffer")?,
            rounds_buffer: register_int_gauge!("rounds_buffer", "size of rounds buffer")?,
            vertex_buffer: register_int_gauge!("vertex_buffer", "size of vertex buffer")?,
            rounds_timed_out: register_int_counter!(
                "timeout_rounds",
                "number of rounds that timed out"
            )?,
        })
    }
}
