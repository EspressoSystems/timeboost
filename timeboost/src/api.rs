use std::{io, sync::Arc, time::Duration};

use ::metrics::prometheus::PrometheusMetrics;
use alloy::{
    consensus::{Transaction, TxEnvelope},
    hex,
    primitives::Keccak256,
    rlp::Decodable,
};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    response::Result,
    routing::{get, post},
};
use bon::Builder;
use http::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_types::{
    Bundle, BundleVariant, ChainId, Epoch, SignedPriorityBundle, ThresholdKeyCell,
};
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
    enc_key: ThresholdKeyCell,
    express_lane: bool,
    metrics: Arc<PrometheusMetrics>,
}

impl ApiServer {
    pub fn router(&self) -> Router {
        let mut router = Router::new();
        router = if self.express_lane {
            router
                .route("/v1/submit/priority", post(submit_priority))
                .route("/v1/submit/regular", post(submit_regular))
        } else {
            router.route("/v1/", post(rpc))
        };
        router.route("/v1/encryption-key", get(encryption_key))
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

async fn rpc(
    server: State<ApiServer>,
    Json(req): Json<JsonRpcRequest>,
) -> Result<Json<JsonRpcResponse<String>>> {
    if req.jsonrpc != "2.0" {
        return Err(StatusCode::BAD_REQUEST.into());
    }

    let id = &req.id;
    if req.method != "eth_sendRawTransaction" && req.method != "eth_sendEncTransaction" {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let raw = req
        .params
        .first()
        .ok_or(StatusCode::BAD_REQUEST)?
        .trim_start_matches("0x");
    let bytes = hex::decode(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);

    let tx_hash_bytes = hasher.finalize();
    if req.method == "eth_sendRawTransaction" {
        let env: TxEnvelope =
            TxEnvelope::decode(&mut &bytes[..]).map_err(|_| StatusCode::BAD_REQUEST)?;

        let chain_id = env.chain_id().ok_or(StatusCode::BAD_REQUEST)?;
        let singleton = vec![bytes];
        let encoded = ssz::ssz_encode(&singleton);
        let b = Bundle::new(ChainId::from(chain_id), Epoch::now(), encoded.into(), false);
        server.submit_bundle(BundleVariant::Regular(b)).await?
    } else {
        let chain_params = req.params.get(1).ok_or(StatusCode::BAD_REQUEST)?;
        let chain_id = chain_params
            .parse::<u64>()
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let b = Bundle::new(chain_id.into(), Epoch::now(), bytes.into(), true);
        server.submit_bundle(BundleVariant::Regular(b)).await?
    }
    let tx_hash = format!("0x{}", hex::encode(tx_hash_bytes));
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: id.to_string(),
        result: tx_hash,
    };
    Ok(Json(response))
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

#[derive(Deserialize, Clone)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<String>,
    id: u64,
}

#[derive(Serialize)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    id: String,
    result: T,
}
