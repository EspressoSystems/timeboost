use prometheus::{IntGauge, register_int_gauge};

#[derive(Debug)]
#[non_exhaustive]
pub struct RbcMetrics {
    pub tx_channel_cap: IntGauge,
    pub rx_channel_cap: IntGauge,
}

impl RbcMetrics {
    pub fn new() -> prometheus::Result<Self> {
        Ok(Self {
            tx_channel_cap: register_int_gauge!(
                "rbc_tx_channel_cap",
                "rbc to app channel capacity"
            )?,
            rx_channel_cap: register_int_gauge!(
                "rbc_rx_channel_cap",
                "app to rbc channel capacity"
            )?,
        })
    }
}
