use anyhow::Result;
use ark_std::rand::rngs::OsRng;
use axum::http::StatusCode;
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use parking_lot::Mutex;
use std::sync::Arc;
use timeboost::contracts::initializer::{ReadyRequest, ReadyResponse, StartResponse};
use timeboost::decryption::{DecryptionScheme, Keyset, TrustedKeygenResult};
use timeboost_crypto::traits::encryption::ThresholdEncScheme;
use timeboost_utils::types::logging;
use tokio::signal;
use tracing::info;
type ReadyState = Arc<Mutex<Vec<ReadyResponse>>>;

#[derive(Parser, Debug)]
struct Cli {
    /// The expected number of nodes to connect
    #[clap(long)]
    committee_size: u16,
    /// The port that the server binds to
    #[clap(long)]
    port: Option<u16>,
}

/// Manager binary emulates the role of the Key Manager in Decentralized Timeboost
///
/// 1. Gather public (signing) key information from nodes in the next keyset.
/// 2. Produce a public (encryption) key and corresponding decryption keys.
/// 3. Update the Key Management contract with signing and decryption keys (TODO).
/// 4. Serve peer information (out-of-band) on its API (TODO).
#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    let state = ReadyState::default();

    let keygen_result = trusted_keygen(cli.committee_size as usize);

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/start/",
            get(move |state| start(state, cli.committee_size)),
        )
        .route(
            "/ready/",
            post(move |state, payload| ready(state, payload, keygen_result)),
        )
        .with_state(state);
    let url = format!("0.0.0.0:{}", cli.port.unwrap_or(7200));
    let listener = tokio::net::TcpListener::bind(url).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn trusted_keygen(committee_size: usize) -> TrustedKeygenResult {
    // TODO: modify keyset id when introducing dynamic keysets
    let keyset = Keyset::new(0, committee_size as u32);
    let parameters = DecryptionScheme::setup(&mut OsRng, keyset).unwrap();
    let (public_key, key_shares) = DecryptionScheme::keygen(&mut OsRng, &parameters).unwrap();
    info!("encryption key: {:?}", public_key.pk);
    TrustedKeygenResult::new(public_key, key_shares)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(
    State(state): State<ReadyState>,
    Json(payload): Json<ReadyRequest>,
    keygen_result: TrustedKeygenResult,
) -> (StatusCode, Json<ReadyResponse>) {
    let node_id = payload.node_id;
    let entry = ReadyResponse {
        node_id,
        ip_addr: payload.node_host,
        public_key: payload.public_key,
        dec_share: keygen_result.key_shares
            [usize::try_from(node_id).expect("unable to get node_id")]
        .clone(),
    };
    let mut state = state.lock();
    state.push(entry.clone());
    (StatusCode::OK, Json(entry))
}

async fn start(state: State<ReadyState>, size: u16) -> (StatusCode, Json<StartResponse>) {
    let ready_responses = state.lock();
    let response = StartResponse {
        started: ready_responses.len() == usize::from(size),
        committee: if ready_responses.len() == usize::from(size) {
            ready_responses.to_vec()
        } else {
            Vec::new()
        },
    };
    (StatusCode::OK, Json(response))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
