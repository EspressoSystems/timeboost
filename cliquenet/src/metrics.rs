use std::collections::HashMap;

use metrics::{Counter, Gauge, Histogram, Metrics, NoMetrics};
use multisig::PublicKey;

#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkMetrics {
    pub connections: Box<dyn Gauge>,
    pub latency: Box<dyn Histogram>,
    pub sent: Box<dyn Counter>,
    pub received: Box<dyn Counter>,
    connects: HashMap<PublicKey, Box<dyn Counter>>,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics, std::iter::empty())
    }
}

impl NetworkMetrics {
    pub fn new<M: Metrics, P>(m: &M, parties: P) -> Self
    where
        P: IntoIterator<Item = PublicKey>,
    {
        let buckets = &[
            0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 75.0, 100.0, 150.0,
            200.0, 500.0,
        ];
        Self {
            latency: m.create_histogram("latency", Some("ms"), Some(buckets)),
            connections: m.create_gauge("connections", None),
            sent: m.create_counter("messages_sent", None),
            received: m.create_counter("messages_received", None),
            connects: parties
                .into_iter()
                .map(|k| (k, m.create_counter(&format!("peer_id_{k}"), None)))
                .collect(),
        }
    }

    pub fn add_connect_attempt(&self, key: &PublicKey) {
        if let Some(ctr) = self.connects.get(key) {
            ctr.add(1)
        }
    }
}
