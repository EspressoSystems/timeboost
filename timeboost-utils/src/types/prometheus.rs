use std::{collections::HashMap, sync::Arc};

use metrics::{
    Counter, CounterFamily, Gauge, GaugeFamily, Histogram, HistogramFamily, Metrics, TextFamily,
};
use parking_lot::RwLock;
use prometheus::{HistogramOpts, TextEncoder};

pub type Result<T> = std::result::Result<T, PrometheusError>;

#[derive(Clone, Debug)]
pub struct TimeboostCounter(prometheus::Counter);

impl Counter for TimeboostCounter {
    fn add(&self, amount: usize) {
        self.0.inc_by(amount as f64);
    }
}

impl TimeboostCounter {
    pub fn new(registry: &prometheus::Registry, opts: prometheus::Opts) -> Result<Self> {
        let counter = prometheus::Counter::with_opts(opts)?;
        registry.register(Box::new(counter.clone()))?;
        Ok(Self(counter))
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
    pub fn new(registry: &prometheus::Registry, opts: prometheus::HistogramOpts) -> Result<Self> {
        let histogram = prometheus::Histogram::with_opts(opts)?;
        registry.register(Box::new(histogram.clone()))?;
        Ok(Self(histogram))
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
    pub fn new(registry: &prometheus::Registry, opts: prometheus::Opts) -> Result<Self> {
        let gauge = prometheus::Gauge::with_opts(opts)?;
        registry.register(Box::new(gauge.clone()))?;
        Ok(Self(gauge))
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
    histograms: Arc<RwLock<HashMap<String, TimeboostHistogram>>>,
    gauges: Arc<RwLock<HashMap<String, TimeboostGauge>>>,
    counters: Arc<RwLock<HashMap<String, TimeboostCounter>>>,
}

impl PrometheusMetrics {
    fn metric_opts(&self, name: &str, unit_label: Option<&str>) -> prometheus::Opts {
        let help = unit_label.unwrap_or(name);
        prometheus::Opts::new(name, help)
    }

    pub fn export(&self) -> Result<String> {
        let metrics = self.registry.gather();
        let text = TextEncoder::new().encode_to_string(&metrics)?;
        Ok(text)
    }
}

impl Metrics for PrometheusMetrics {
    fn create_counter(&self, name: &str, unit_label: Option<&str>) -> Box<dyn Counter> {
        let opts = self.metric_opts(name, unit_label);
        let counter = match TimeboostCounter::new(&self.registry, opts) {
            Ok(ctr) => ctr,
            Err(er) => {
                panic!("Failed to create counter \"{name}\": {er}")
            }
        };
        self.counters
            .write()
            .insert(name.to_string(), counter.clone());
        Box::new(counter)
    }

    fn create_gauge(&self, name: &str, unit_label: Option<&str>) -> Box<dyn Gauge> {
        let opts = self.metric_opts(name, unit_label);
        let gauge = match TimeboostGauge::new(&self.registry, opts) {
            Ok(gau) => gau,
            Err(er) => {
                panic!("Failed to create gauge \"{name}\": {er}")
            }
        };
        self.gauges.write().insert(name.to_string(), gauge.clone());
        Box::new(gauge)
    }

    fn create_histogram(
        &self,
        name: &str,
        unit_label: Option<&str>,
        buckets: Option<&[f64]>,
    ) -> Box<dyn Histogram> {
        let opts = self.metric_opts(name, unit_label);
        let histogram_opts = buckets.map_or_else(
            || opts.clone().into(),
            |b| HistogramOpts {
                common_opts: opts.clone(),
                buckets: b.to_vec(),
            },
        );
        let histogram = match TimeboostHistogram::new(&self.registry, histogram_opts) {
            Ok(hs) => hs,
            Err(e) => {
                panic!("Failed to create histogram \"{name}\": {e}")
            }
        };
        self.histograms
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
