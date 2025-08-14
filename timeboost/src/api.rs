use std::{io, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use bon::Builder;
use http::{Request, Response, StatusCode};
use timeboost_crypto::prelude::{ThresholdEncKey, ThresholdEncKeyCell};
use timeboost_types::{Bundle, BundleVariant, SignedPriorityBundle};
use timeboost_utils::types::prometheus::PrometheusMetrics;
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
    enc_key: ThresholdEncKeyCell,
    metrics: Arc<PrometheusMetrics>,
}

impl ApiServer {
    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/submit/priority", post(Self::submit_priority))
            .route("/v1/submit/regular", post(Self::submit_regular))
            .route("/v1/encryption-key", get(Self::encryption_key))
            .route("/i/health", get(Self::health))
            .route("/i/metrics", get(Self::metrics))
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
                        .on_response(|r: &Response<Body>, d: Duration, _span: &Span| {
                            debug!(status = %r.status().as_u16(), duration = ?d, "response created")
                        })
                )
            )
    }

    pub async fn serve<A: ToSocketAddrs>(self, addr: A) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, self.router()).await
    }

    async fn health(this: State<Self>) -> StatusCode {
        if this.bundles.is_closed() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::OK
        }
    }

    async fn submit_priority(
        this: State<Self>,
        bundle: Json<SignedPriorityBundle>,
    ) -> (StatusCode, &'static str) {
        match this.bundles.send(BundleVariant::Priority(bundle.0)).await {
            Ok(()) => (StatusCode::OK, "priority bundle enqueued"),
            Err(_) => {
                error!("bundle channel is closed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to enqueue priority bundle",
                )
            }
        }
    }

    async fn submit_regular(this: State<Self>, bundle: Json<Bundle>) -> (StatusCode, &'static str) {
        match this.bundles.send(BundleVariant::Regular(bundle.0)).await {
            Ok(()) => (StatusCode::OK, "bundle enqueued"),
            Err(_) => {
                error!("bundle channel is closed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to enqueue bundle",
                )
            }
        }
    }

    async fn encryption_key(this: State<Self>) -> Json<ThresholdEncKey> {
        Json(this.enc_key.read().await)
    }

    async fn metrics(this: State<Self>) -> impl IntoResponse {
        match this.metrics.export() {
            Ok(output) => (StatusCode::OK, output).into_response(),
            Err(err) => {
                error!(%err, "metrics export error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to export metrics",
                )
                    .into_response()
            }
        }
    }
}
