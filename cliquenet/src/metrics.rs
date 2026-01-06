use std::{collections::HashMap, time::Duration};

use multisig::PublicKey;
use prometheus::{IntCounter, IntGauge, opts, register_int_counter, register_int_gauge};

#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkMetrics {
    pub connections: IntGauge,
    pub iqueue: IntGauge,
    pub oqueue: IntGauge,
    connects: HashMap<PublicKey, IntCounter>,
    latencies: HashMap<PublicKey, IntGauge>,
    peer_oqueues: HashMap<PublicKey, IntGauge>,
    peer_iqueues: HashMap<PublicKey, IntGauge>,
}

impl NetworkMetrics {
    pub fn new<P>(label: &str, parties: P) -> prometheus::Result<Self>
    where
        P: IntoIterator<Item = PublicKey>,
    {
        let connects = parties
            .into_iter()
            .map(|k| {
                let o = opts!("connect_attempts", "number of connect attempts")
                    .const_label("label", label)
                    .const_label("peer", k.to_string());
                Ok::<_, prometheus::Error>((k, register_int_counter!(o)?))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let latencies = connects
            .keys()
            .copied()
            .map(|k| {
                let o = opts!("latency_ms", "peer latency")
                    .const_label("label", label)
                    .const_label("peer", k.to_string());
                Ok::<_, prometheus::Error>((k, register_int_gauge!(o)?))
            })
            .collect::<Result<_, _>>()?;

        let peer_oqueues = connects
            .keys()
            .copied()
            .map(|k| {
                let o = opts!("peer_oqueue_cap", "peer oqueue capacity")
                    .const_label("label", label)
                    .const_label("peer", k.to_string());
                Ok::<_, prometheus::Error>((k, register_int_gauge!(o)?))
            })
            .collect::<Result<_, _>>()?;

        let peer_iqueues = connects
            .keys()
            .copied()
            .map(|k| {
                let o = opts!("peer_iqueue_cap", "peer iqueue capacity")
                    .const_label("label", label)
                    .const_label("peer", k.to_string());
                Ok::<_, prometheus::Error>((k, register_int_gauge!(o)?))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            connections: register_int_gauge!(
                &format!("{label}_connections"),
                "number of peer connections"
            )?,
            iqueue: register_int_gauge!(&format!("{label}_iqueue_cap"), "inbound queue capacity")?,
            oqueue: register_int_gauge!(&format!("{label}_oqueue_cap"), "outbound queue capacity")?,
            connects,
            latencies,
            peer_oqueues,
            peer_iqueues,
        })
    }

    pub fn add_connect_attempt(&self, k: &PublicKey) {
        if let Some(c) = self.connects.get(k) {
            c.inc()
        }
    }

    pub fn set_latency(&self, k: &PublicKey, d: Duration) {
        if let Some(g) = self.latencies.get(k) {
            g.set(d.as_millis() as i64)
        }
    }

    pub fn set_peer_oqueue_cap(&self, k: &PublicKey, n: usize) {
        if let Some(g) = self.peer_oqueues.get(k) {
            g.set(n as i64)
        }
    }

    pub fn set_peer_iqueue_cap(&self, k: &PublicKey, n: usize) {
        if let Some(g) = self.peer_iqueues.get(k) {
            g.set(n as i64)
        }
    }
}
