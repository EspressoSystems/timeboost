use std::{collections::BTreeMap, time::{Duration, Instant}};

use parking_lot::Mutex;

static __TIMERS: Mutex<BTreeMap<&str, TimeSeries>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Debug, Default)]
pub struct TimeSeries {
    times: BTreeMap<u64, Instant>,
}

impl TimeSeries {
    pub fn records(&self) -> impl Iterator<Item = (u64, Instant)> {
        self.times.iter().map(|(k, v)| (*k, *v))
    }

    pub fn deltas(&self) -> impl Iterator<Item = (u64, Duration)> {
        self.records()
            .zip(self.records().skip(1))
            .map(|(fst, snd)| (snd.0, snd.1.duration_since(fst.1)))
    }
}

pub fn time_series(name: &str) -> Option<TimeSeries> {
    __TIMERS.lock().get(name).cloned()
}

pub fn take_time_series(name: &str) -> Option<TimeSeries> {
    __TIMERS.lock().remove(name)
}

pub fn record(series: &'static str, key: u64) {
    __TIMERS
        .lock()
        .entry(series)
        .or_default()
        .times
        .insert(key, Instant::now());
}

pub fn record_once(series: &'static str, key: u64) {
    __TIMERS
        .lock()
        .entry(series)
        .or_default()
        .times
        .entry(key)
        .or_insert_with(Instant::now);
}
