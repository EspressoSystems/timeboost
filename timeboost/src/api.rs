use std::{io, sync::Arc, time::Duration};

use ::metrics::prometheus::PrometheusMetrics;
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    response::Result,
    routing::{get, post},
};
use bon::Builder;
use http::{Request, Response, StatusCode};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_types::{Bundle, BundleVariant, DecryptionKeyCell, SignedPriorityBundle};
use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::mpsc::Sender,
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_http::{ServiceBuilderExt, request_id::MakeRequestUuid};
use tracing::{Level, Span, debug, error, span};

pub mod internal;

#[derive(Debug, Clone, Builder)]
pub struct ApiServer {
    bundles: Sender<BundleVariant>,
    enc_key: DecryptionKeyCell,
    metrics: Arc<PrometheusMetrics>,
}

impl ApiServer {
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/submit/priority", post(submit_priority))
            .route("/v1/submit/regular", post(submit_regular))
            .route("/v1/encryption-key", get(encryption_key))
            .route("/i/health", get(health))
            .route("/i/metrics", get(metrics))
            .with_state(self.clone())
            .layer(
                ServiceBuilder::new()
                    .set_x_request_id(MakeRequestUuid)
                    .layer(TraceLayer::new_for_http()
                        .make_span_with(|r: &Request<Body>| {
                            span!(
                                Level::DEBUG,
                                "request",
                                method = %r.method(),
                                uri = %r.uri(),
                                id = %r.headers()
                                    .get("x-request-id")
                                    .and_then(|id| id.to_str().ok())
                                    .unwrap_or("N/A")
                            )
                        })
                        .on_request(|_r: &Request<Body>, _s: &Span| {
                            debug!("request received")
                        })
                        .on_response(|r: &Response<Body>, d: Duration, _s: &Span| {
                            debug!(status = %r.status().as_u16(), duration = ?d, "response created")
                        })
                )
            )
    }

    pub async fn serve<A: ToSocketAddrs>(self, addr: A) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, self.router()).await
    }

    async fn submit_bundle(&self, bundle: BundleVariant) -> Result<()> {
        if self.bundles.send(bundle).await.is_err() {
            error!("bundle channel is closed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
        }
        Ok(())
    }
}

async fn submit_priority(server: State<ApiServer>, json: Json<SignedPriorityBundle>) -> Result<()> {
    server.submit_bundle(BundleVariant::Priority(json.0)).await
}

async fn submit_regular(server: State<ApiServer>, json: Json<Bundle>) -> Result<()> {
    server.submit_bundle(BundleVariant::Regular(json.0)).await
}

async fn encryption_key(server: State<ApiServer>) -> Json<ThresholdEncKey> {
    Json(server.enc_key.read().await.pubkey().clone())
}

async fn metrics(server: State<ApiServer>) -> Result<String> {
    match server.metrics.export() {
        Ok(output) => Ok(output),
        Err(err) => {
            error!(%err, "metrics export error");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into())
        }
    }
}

async fn health(server: State<ApiServer>) -> Result<()> {
    if server.bundles.is_closed() {
        error!("bundle channel is closed");
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
    }
    Ok(())
}
