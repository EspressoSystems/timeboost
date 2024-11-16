use std::borrow::Cow;

use async_lock::RwLock;
use futures::FutureExt;
use tide_disco::{error::ServerError, App};
use timeboost_core::types::metrics::ConsensusMetrics;
use toml::toml;
use vbs::version::StaticVersionType;

pub async fn serve<ApiVer: StaticVersionType + 'static>(port: u16, metrics: ConsensusMetrics) {
    let api = toml! {
        [route.metrics]
        PATH = ["/metrics"]
        METHOD = "METRICS"
    };
    // let mut app = App::<_, ServerError>::with_state(RwLock::new(metrics));
    // app.module::<ServerError, ApiVer>("status", api)
    //     .unwrap()
    //     .metrics("metrics", |_req, state| {
    //         async move { Ok(Cow::Borrowed(state)) }.boxed()
    //     })
    //     .unwrap();
    // if let Err(err) = app
    //     .serve(format!("0.0.0.0:{port}"), ApiVer::instance())
    //     .await
    // {
    //     tracing::error!("web server exited unexpectedly: {err:#}");
    // }
}
