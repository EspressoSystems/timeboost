use std::{collections::HashMap, time::Duration};

use metrics::{Counter, Gauge, Metrics, NoMetrics};
use multisig::PublicKey;

#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkMetrics {
    pub connections: Box<dyn Gauge>,
    pub iqueue: Box<dyn Gauge>,
    pub oqueue: Box<dyn Gauge>,
    // TODO: These should use prometheus labels to model multiple dimensions:
    connects: HashMap<PublicKey, Box<dyn Counter>>,
    latencies: HashMap<PublicKey, Box<dyn Gauge>>,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self::new("default", &NoMetrics, std::iter::empty())
    }
}

impl NetworkMetrics {
    pub fn new<M: Metrics, P>(label: &str, m: &M, parties: P) -> Self
    where
        P: IntoIterator<Item = PublicKey>,
    {
        let connects = parties
            .into_iter()
            .map(|k| {
                let c = m.create_counter(&format!("{label}_{k}_connect_attempts"), None);
                (k, c)
            })
            .collect::<HashMap<_, _>>();

        let latencies = connects
            .keys()
            .copied()
            .map(|k| {
                let g = m.create_gauge(&format!("{label}_{k}_latency"), Some("ms"));
                (k, g)
            })
            .collect();

        Self {
            connections: m.create_gauge(&format!("{label}_connections"), None),
            iqueue: m.create_gauge(&format!("{label}_iqueue"), None),
            oqueue: m.create_gauge(&format!("{label}_oqueue"), None),
            connects,
            latencies,
        }
    }

    pub fn add_connect_attempt(&self, key: &PublicKey) {
        if let Some(ctr) = self.connects.get(key) {
            ctr.add(1)
        }
    }

    pub fn set_latency(&self, key: &PublicKey, d: Duration) {
        if let Some(g) = self.latencies.get(key) {
            g.set(d.as_millis() as usize)
        }
    }
}
