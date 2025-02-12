use std::collections::HashMap;

use multisig::PublicKey;
use timeboost_utils::traits::metrics::{Counter, Gauge, Histogram, Metrics, NoMetrics};

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
        Self {
            latency: m.create_histogram("latency", Some("ms")),
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
