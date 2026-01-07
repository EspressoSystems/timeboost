use std::{collections::HashMap, time::Duration};

use multisig::PublicKey;
use prometheus::{IntCounter, IntGauge, opts, register_int_counter, register_int_gauge};
use prometheus::{Result, unregister};

#[derive(Debug, Clone)]
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
    pub fn new<P>(label: &str, parties: P) -> Result<Self>
    where
        P: IntoIterator<Item = PublicKey>,
    {
        let connects = parties
            .into_iter()
            .map(|k| Ok((k, reg_connect_attempts(label, &k)?)))
            .collect::<Result<HashMap<_, _>>>()?;

        let latencies = connects
            .keys()
            .copied()
            .map(|k| Ok((k, reg_latency(label, &k)?)))
            .collect::<Result<HashMap<_, _>>>()?;

        let peer_oqueues = connects
            .keys()
            .copied()
            .map(|k| Ok((k, reg_ocap(label, &k)?)))
            .collect::<Result<HashMap<_, _>>>()?;

        let peer_iqueues = connects
            .keys()
            .copied()
            .map(|k| Ok((k, reg_icap(label, &k)?)))
            .collect::<Result<HashMap<_, _>>>()?;

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

    pub fn add_parties<P>(&mut self, label: &str, parties: P) -> Result<()>
    where
        P: IntoIterator<Item = PublicKey>,
    {
        for k in parties {
            if !self.connects.contains_key(&k) {
                self.connects.insert(k, reg_connect_attempts(label, &k)?);
            }
            if !self.latencies.contains_key(&k) {
                self.latencies.insert(k, reg_latency(label, &k)?);
            }
            if !self.peer_oqueues.contains_key(&k) {
                self.peer_oqueues.insert(k, reg_ocap(label, &k)?);
            }
            if !self.peer_iqueues.contains_key(&k) {
                self.peer_iqueues.insert(k, reg_icap(label, &k)?);
            }
        }
        Ok(())
    }

    pub fn remove_parties<'a, P>(&mut self, parties: P)
    where
        P: IntoIterator<Item = &'a PublicKey>,
    {
        for k in parties {
            if let Some(x) = self.connects.remove(k) {
                let _ = unregister(Box::new(x));
            }
            if let Some(x) = self.latencies.remove(k) {
                let _ = unregister(Box::new(x));
            }
            if let Some(x) = self.peer_oqueues.remove(k) {
                let _ = unregister(Box::new(x));
            }
            if let Some(x) = self.peer_iqueues.remove(k) {
                let _ = unregister(Box::new(x));
            }
        }
    }
}

fn reg_connect_attempts(label: &str, k: &PublicKey) -> Result<IntCounter> {
    let opt = opts!("connect_attempts", "number of connect attempts")
        .const_label("label", label)
        .const_label("peer", k.to_string());
    register_int_counter!(opt)
}

fn reg_latency(label: &str, k: &PublicKey) -> Result<IntGauge> {
    let opt = opts!("latency_ms", "peer latency")
        .const_label("label", label)
        .const_label("peer", k.to_string());
    register_int_gauge!(opt)
}

fn reg_ocap(label: &str, k: &PublicKey) -> Result<IntGauge> {
    let opt = opts!("peer_oqueue_cap", "peer oqueue capacity")
        .const_label("label", label)
        .const_label("peer", k.to_string());
    register_int_gauge!(opt)
}

fn reg_icap(label: &str, k: &PublicKey) -> Result<IntGauge> {
    let opt = opts!("peer_iqueue_cap", "peer iqueue capacity")
        .const_label("label", label)
        .const_label("peer", k.to_string());
    register_int_gauge!(opt)
}
