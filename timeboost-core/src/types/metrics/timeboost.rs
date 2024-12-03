use std::collections::{hash_map::Entry, HashMap};

use timeboost_utils::traits::metrics::{
    Counter, CounterFamily, Gauge, Histogram, Metrics, NoMetrics,
};

use crate::types::time::Epoch;

#[derive(Debug)]
#[non_exhaustive]
pub struct TimeboostMetrics {
    pub epoch: Box<dyn Gauge>,
    pub epoch_duration: Box<dyn Histogram>,
    pub failed_epochs: Box<dyn CounterFamily>,
    pub failures_in_epoch: HashMap<Epoch, Box<dyn Counter>>,
}

impl Default for TimeboostMetrics {
    fn default() -> Self {
        Self::new(&NoMetrics)
    }
}

impl TimeboostMetrics {
    pub fn new<M: Metrics>(m: &M) -> Self {
        Self {
            epoch: m.create_gauge("epoch".to_string(), None),
            epoch_duration: m.create_histogram("epoch_duration".to_string(), None),
            failed_epochs: m.counter_family("failed_epochs".to_string(), vec!["epoch".into()]),
            failures_in_epoch: HashMap::new(),
        }
    }

    pub fn get_failures_in_epoch(&mut self, epoch: Epoch) -> &mut Box<dyn Counter> {
        if let Entry::Vacant(e) = self.failures_in_epoch.entry(epoch) {
            e.insert(self.failed_epochs.create(vec![epoch.to_string()]));
        }

        self.failures_in_epoch.get_mut(&epoch).unwrap()
    }

    pub fn collect_garbage(&mut self, epoch: Epoch) {
        self.failures_in_epoch.retain(|e, _| *e > epoch);
    }
}
