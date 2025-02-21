use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::future::BoxFuture;
use metrics::{
    Counter, CounterFamily, Gauge, GaugeFamily, Histogram, HistogramFamily, Metrics, TextFamily,
};
use parking_lot::RwLock;
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
    fn metric_opts(&self, name: &str, unit_label: Option<&str>) -> prometheus::Opts {
        let help = unit_label.unwrap_or(name);
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
    fn create_counter(&self, name: &str, unit_label: Option<&str>) -> Box<dyn Counter> {
        let opts = self.metric_opts(name, unit_label);
        let counter = TimeboostCounter::new(&self.registry, opts);
        self.counters
            .write()
            .insert(name.to_string(), counter.clone());
        Box::new(counter)
    }

    fn create_gauge(&self, name: &str, unit_label: Option<&str>) -> Box<dyn Gauge> {
        let opts = self.metric_opts(name, unit_label);
        let gauge = TimeboostGauge::new(&self.registry, opts);
        self.gauges.write().insert(name.to_string(), gauge.clone());
        Box::new(gauge)
    }

    fn create_histogram(&self, name: &str, unit_label: Option<&str>) -> Box<dyn Histogram> {
        let opts = self.metric_opts(name, unit_label);
        let histogram = TimeboostHistogram::new(&self.registry, opts);
        self.historgrams
            .write()
            .insert(name.to_string(), histogram.clone());
        Box::new(histogram)
    }

    /////////////// We don't care about the rest of these
    fn create_text(&self, _name: &str) {
        todo!()
    }

    fn counter_family(&self, _name: &str, _labels: &[&str]) -> Box<dyn CounterFamily> {
        todo!()
    }

    fn gauge_family(&self, _name: &str, _labels: &[&str]) -> Box<dyn GaugeFamily> {
        todo!()
    }

    fn histogram_family(&self, _name: &str, _labels: &[&str]) -> Box<dyn HistogramFamily> {
        todo!()
    }

    fn text_family(&self, _name: &str, _labels: &[&str]) -> Box<dyn TextFamily> {
        todo!()
    }

    fn subgroup(&self, _subgroup_name: &str) -> Box<dyn Metrics> {
        todo!()
    }
}
