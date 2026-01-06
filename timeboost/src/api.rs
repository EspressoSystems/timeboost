use std::{io, time::Duration};

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
use cliquenet::Address;
use http::{Request, Response, StatusCode};
#[cfg(feature = "metrics")]
use prometheus::TextEncoder;
use serde::Deserialize;
use serde_json::{Value, json};
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_types::{Bundle, BundleVariant, Epoch, SignedPriorityBundle, ThresholdKeyCell};
use tokio::{
    net::{TcpListener, ToSocketAddrs},
    sync::mpsc::Sender,
};
use tower::{ServiceBuilder, util::Either};
use tower_http::{ServiceBuilderExt, request_id::MakeRequestUuid};
use tower_http::{auth::AsyncRequireAuthorizationLayer, trace::TraceLayer};
use tracing::{Level, Span, debug, error, span};

use crate::api::auth::Authorize;

mod auth;
pub mod internal;

#[derive(Debug, Clone, Builder)]
pub struct ApiServer {
    upstream_addr: Address,
    bundles: Sender<BundleVariant>,
    enc_key: ThresholdKeyCell,
    express_lane: bool,
    secret: Option<String>,
}

impl ApiServer {
    pub fn router(&self) -> Router {
        let router = if self.express_lane {
            Router::new()
                .route("/v1/submit/priority", post(submit_priority))
                .route("/v1/submit/regular", post(submit_regular))
        } else {
            Router::new()
        };
        router
            .route("/v1/", post(rpc))
            .route("/v1/encryption-key", get(encryption_key))
            .route("/i/health", get(health))
            .route("/i/metrics", get(metrics))
            .with_state(self.clone())
            .layer({
                let builder = ServiceBuilder::new()
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
                    );
                if let Some(secret) = &self.secret {
                    let auth = AsyncRequireAuthorizationLayer::new(Authorize::new(secret.clone()));
                    Either::Right(builder.layer(auth))
                } else {
                    Either::Left(builder)
                }
            })
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
) -> Result<axum::Json<Value>> {
    if req.jsonrpc != "2.0" {
        return Err(StatusCode::BAD_REQUEST.into());
    }

    match req.method.as_str() {
        "eth_sendRawTransaction" => handle_raw_tx(&server, req).await,
        "eth_sendEncTransaction" => handle_enc_tx(&server, req).await,
        _ => {
            let upstream = server.upstream_addr.clone();
            let response = proxy_rpc_call(&upstream, req).await?;

            Ok(Json(response))
        }
    }
}

async fn handle_raw_tx(server: &ApiServer, req: JsonRpcRequest) -> Result<Json<Value>> {
    let params = req.params.ok_or(StatusCode::BAD_REQUEST)?;
    let raw = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .trim_start_matches("0x");

    let bytes = hex::decode(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
    let env = TxEnvelope::decode(&mut &bytes[..]).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    let tx_hash_bytes = hasher.finalize();

    let chain_id = env.chain_id().ok_or(StatusCode::BAD_REQUEST)?;
    let encoded = ssz::ssz_encode(&vec![bytes.clone()]);
    let bundle = Bundle::new(chain_id.into(), Epoch::now(), encoded.into(), false);
    server.submit_bundle(BundleVariant::Regular(bundle)).await?;

    Ok(Json(json! ({
        "jsonrpc": "2.0".to_string(),
        "id": req.id.to_string(),
        "result": json!(hex::encode_prefixed(tx_hash_bytes)),
    })))
}

async fn handle_enc_tx(server: &ApiServer, req: JsonRpcRequest) -> Result<Json<Value>> {
    let params = req.params.ok_or(StatusCode::BAD_REQUEST)?;
    let raw = params
        .first()
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .trim_start_matches("0x");

    let bytes = hex::decode(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
    let chain_id = params
        .get(1)
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?
        .parse::<u64>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    let tx_hash_bytes = hasher.finalize();

    let bundle = Bundle::new(chain_id.into(), Epoch::now(), bytes.into(), true);
    server.submit_bundle(BundleVariant::Regular(bundle)).await?;

    Ok(Json(json! ({
        "jsonrpc": "2.0".to_string(),
        "id": req.id.to_string(),
        "result": json!(hex::encode_prefixed(tx_hash_bytes)),
    })))
}

async fn proxy_rpc_call(upstream: &Address, req: JsonRpcRequest) -> Result<Value> {
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{upstream}"))
        .json(&req)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    if !resp.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY.into());
    }

    resp.json::<Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY.into())
}

async fn encryption_key(server: State<ApiServer>) -> Json<ThresholdEncKey> {
    Json(server.enc_key.read().await.pubkey().clone())
}

async fn metrics() -> Result<String> {
    #[cfg(feature = "metrics")]
    match TextEncoder::new().encode_to_string(&prometheus::gather()) {
        Ok(output) => Ok(output),
        Err(err) => {
            error!(%err, "metrics export error");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into())
        }
    }
    #[cfg(not(feature = "metrics"))]
    Err(StatusCode::NO_CONTENT.into())
}

async fn health(server: State<ApiServer>) -> Result<()> {
    if server.bundles.is_closed() {
        error!("bundle channel is closed");
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Clone, serde::Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Vec<serde_json::Value>>,
    id: serde_json::Value,
}
