use std::{borrow::Cow, sync::Arc};

use futures::FutureExt;
use tide_disco::{error::ServerError, App};
use timeboost_core::types::metrics::prometheus::PrometheusMetrics;
use toml::toml;
use vbs::version::StaticVersionType;

pub async fn serve_metrics_api<ApiVer: StaticVersionType + 'static>(
    port: u16,
    metrics: Arc<PrometheusMetrics>,
) {
    let api = toml! {
        [route.metrics]
        PATH = ["/metrics"]
        METHOD = "METRICS"
    };
    let mut app = App::<_, ServerError>::with_state(metrics);
    app.module::<ServerError, ApiVer>("status", api)
        .unwrap()
        .metrics("metrics", |_req, state| {
            async move { Ok(Cow::Borrowed(state)) }.boxed()
        })
        .unwrap();
    if let Err(err) = app
        .serve(format!("0.0.0.0:{port}"), ApiVer::instance())
        .await
    {
        tracing::error!("web server exited unexpectedly: {err:#}");
    }
}
