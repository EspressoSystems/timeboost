use metrics::{Counter, Histogram, Metrics, NoMetrics};
use std::time::Duration;

#[derive(Debug)]
#[non_exhaustive]
pub struct RbcMetrics {
    /// The time it takes for a message to be RBC-delivered to the application.
    pub delivery_duration: Box<dyn Histogram>,
    /// The time it takes for a message to be acknowledged by all parties.
    pub ack_duration: Box<dyn Histogram>,
    /// The number of retries when sending messages or acks.
    pub retries: Box<dyn Counter>,
}

impl Default for RbcMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl RbcMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            delivery_duration: m.create_histogram("delivery_duration", Some("seconds"), None),
            ack_duration: m.create_histogram("ack_duration", Some("seconds"), None),
            retries: m.create_counter("retries", None),
        }
    }

    pub fn add_delivery_duration(&self, d: Duration) {
        self.delivery_duration.add_point(d.as_secs_f64())
    }

    pub fn add_ack_duration(&self, d: Duration) {
        self.ack_duration.add_point(d.as_secs_f64())
    }
}
