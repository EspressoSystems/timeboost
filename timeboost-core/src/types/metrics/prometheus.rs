use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use futures_core::future::BoxFuture;
use hotshot_types::traits::metrics::{
    Counter, CounterFamily, Gauge, GaugeFamily, Histogram, HistogramFamily, Metrics, TextFamily,
};
use prometheus::{Encoder, TextEncoder};
use tide_disco::method::ReadState;

#[derive(Clone, Debug)]
pub struct TimeboostCounter(prometheus::Counter);
impl Counter for TimeboostCounter {
    fn add(&self, amount: usize) {
        self.0.inc_by(amount as f64);
    }
}
impl TimeboostCounter {
    pub fn new(registry: &prometheus::Registry, opts: prometheus::Opts) -> Self {
        let counter = prometheus::Counter::with_opts(opts).expect("failed to create counter");
        registry
            .register(Box::new(counter.clone()))
            .expect("failed to register counter");
        Self(counter)
    }
}

#[derive(Clone, Debug)]
pub struct TimeboostHistogram(prometheus::Histogram);
impl Histogram for TimeboostHistogram {
    fn add_point(&self, point: f64) {
        self.0.observe(point);
    }
}
impl TimeboostHistogram {
    pub fn new(registry: &prometheus::Registry, opts: prometheus::Opts) -> Self {
        let histogram =
            prometheus::Histogram::with_opts(opts.into()).expect("failed to create histogram");
        registry
            .register(Box::new(histogram.clone()))
            .expect("failed to register histogram");
        Self(histogram)
    }
}

#[derive(Clone, Debug)]
pub struct TimeboostGauge(prometheus::Gauge);
impl Gauge for TimeboostGauge {
    fn set(&self, amount: usize) {
        self.0.set(amount as f64);
    }

    fn update(&self, delts: i64) {
        self.0.add(delts as f64);
    }
}
impl TimeboostGauge {
    pub fn new(registry: &prometheus::Registry, opts: prometheus::Opts) -> Self {
        let gauge = prometheus::Gauge::with_opts(opts).expect("failed to create gauge");
        registry
            .register(Box::new(gauge.clone()))
            .expect("failed to register gauge");
        Self(gauge)
    }
}

#[derive(Debug)]
pub struct PrometheusError(anyhow::Error);
impl std::fmt::Display for PrometheusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PrometheusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}
impl From<prometheus::Error> for PrometheusError {
    fn from(source: prometheus::Error) -> Self {
        Self(anyhow::anyhow!(source))
    }
}

#[derive(Clone, Debug, Default)]
pub struct PrometheusMetrics {
    registry: prometheus::Registry,
    historgrams: Arc<RwLock<HashMap<String, TimeboostHistogram>>>,
    gauges: Arc<RwLock<HashMap<String, TimeboostGauge>>>,
    counters: Arc<RwLock<HashMap<String, TimeboostCounter>>>,
}

impl PrometheusMetrics {
    fn metric_opts(&self, name: String, unit_label: Option<String>) -> prometheus::Opts {
        let help = unit_label.unwrap_or_else(|| name.clone());
        prometheus::Opts::new(name, help)
    }
}
impl tide_disco::metrics::Metrics for PrometheusMetrics {
    type Error = PrometheusError;

    fn export(&self) -> Result<String, Self::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer)?;
        String::from_utf8(buffer).map_err(|err| {
            PrometheusError(anyhow::anyhow!(
                "could not convert Prometheus output to UTF-8: {}",
                err
            ))
        })
    }
}

#[async_trait]
impl ReadState for PrometheusMetrics {
    /// The type of state which this type allows a caller to read.
    type State = Self;

    async fn read<T>(
        &self,
        op: impl Send + for<'a> FnOnce(&'a Self::State) -> BoxFuture<'a, T> + 'async_trait,
    ) -> T {
        op(self).await
    }
}

impl Metrics for PrometheusMetrics {
    fn create_counter(&self, name: String, unit_label: Option<String>) -> Box<dyn Counter> {
        let opts = self.metric_opts(name.clone(), unit_label);
        let counter = TimeboostCounter::new(&self.registry, opts);
        self.counters
            .write()
            .unwrap()
            .insert(name.clone(), counter.clone());
        Box::new(counter)
    }

    fn create_gauge(&self, name: String, unit_label: Option<String>) -> Box<dyn Gauge> {
        let opts = self.metric_opts(name.clone(), unit_label);
        let gauge = TimeboostGauge::new(&self.registry, opts);
        self.gauges
            .write()
            .unwrap()
            .insert(name.clone(), gauge.clone());
        Box::new(gauge)
    }

    fn create_histogram(&self, name: String, unit_label: Option<String>) -> Box<dyn Histogram> {
        let opts = self.metric_opts(name.clone(), unit_label);
        let histogram = TimeboostHistogram::new(&self.registry, opts);
        self.historgrams
            .write()
            .unwrap()
            .insert(name.clone(), histogram.clone());
        Box::new(histogram)
    }

    /////////////// We don't care about the rest of these
    fn create_text(&self, _name: String) {
        todo!()
    }

    fn counter_family(&self, _name: String, _labels: Vec<String>) -> Box<dyn CounterFamily> {
        todo!()
    }

    fn gauge_family(&self, _name: String, _labels: Vec<String>) -> Box<dyn GaugeFamily> {
        todo!()
    }

    fn histogram_family(&self, _name: String, _labels: Vec<String>) -> Box<dyn HistogramFamily> {
        todo!()
    }

    fn text_family(&self, _name: String, _labels: Vec<String>) -> Box<dyn TextFamily> {
        todo!()
    }

    fn subgroup(&self, _subgroup_name: String) -> Box<dyn Metrics> {
        todo!()
    }
}
