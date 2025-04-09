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
    pub sent_message_len: Box<dyn Histogram>,
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
        let latencies = &[
            0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 75.0, 100.0, 150.0,
            200.0, 500.0,
        ];

        let sizes = &[
            1024.0,
            16.0 * 1024.0,
            64.0 * 1024.0,
            256.0 * 1024.0,
            512.0 * 1024.0,
            1024.0 * 1024.0,
            2048.0 * 1024.0,
            4096.0 * 1024.0,
            5120.0 * 1024.0,
        ];

        Self {
            latency: m.create_histogram("latency", Some("ms"), Some(latencies)),
            connections: m.create_gauge("connections", None),
            sent_message_len: m.create_histogram("sent_msg_len", Some("bytes"), Some(sizes)),
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
