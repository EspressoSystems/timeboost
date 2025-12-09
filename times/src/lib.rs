use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

/// Max. number of records to keep per time series.
const MAX_SIZE: usize = 1000;

static TIMERS: Mutex<BTreeMap<&str, TimeSeries>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Debug, Default)]
pub struct TimeSeries {
    times: BTreeMap<u64, Instant>,
}

impl TimeSeries {
    pub fn records(&self) -> &BTreeMap<u64, Instant> {
        &self.times
    }

    pub fn deltas(&self) -> impl Iterator<Item = (u64, Duration)> {
        self.times
            .iter()
            .zip(self.times.iter().skip(1))
            .map(|(fst, snd)| (*snd.0, snd.1.duration_since(*fst.1)))
    }
}

pub fn time_series(name: &str) -> Option<TimeSeries> {
    TIMERS.lock().get(name).cloned()
}

pub fn take_time_series(name: &str) -> Option<TimeSeries> {
    TIMERS.lock().remove(name)
}

pub fn record(series: &'static str, key: u64) {
    let mut timers = TIMERS.lock();
    if timers.len() == MAX_SIZE {
        timers.pop_first();
    }
    timers
        .entry(series)
        .or_default()
        .times
        .insert(key, Instant::now());
}

pub fn record_once(series: &'static str, key: u64) {
    let mut timers = TIMERS.lock();
    if timers.len() == MAX_SIZE {
        timers.pop_first();
    }
    timers
        .entry(series)
        .or_default()
        .times
        .entry(key)
        .or_insert_with(Instant::now);
}
