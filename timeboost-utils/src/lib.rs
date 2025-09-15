pub mod enc_key;
pub mod load_generation;
pub mod types;
pub mod until;

use std::time::Duration;

use cliquenet::Address;
use multisig::x25519;
use tokio::time::sleep;
use tracing::{error, info};

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    sig_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn unsafe_zero_dh_keypair<N: Into<u64>>(i: N) -> x25519::Keypair {
    dh_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn sig_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(new_seed)
}

pub fn dh_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> x25519::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    x25519::Keypair::from_seed(new_seed).unwrap()
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

/// NON PRODUCTION
/// This function takes the provided host and hits the health endpoint. This to ensure that when
/// initiating the network TCP stream that we do not try to hit a dead host, causing issues with
/// network startup.
pub async fn wait_for_live_peer(host: &Address) -> anyhow::Result<()> {
    if host.is_ip() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    let url = format!("http://{host}/i/health");

    loop {
        info!(%host, %url, "establishing connection to load balancer");
        match client.get(&url).send().await {
            Ok(resp) => {
                info!(response = ?resp, "got response");
                if resp.status() == 200 {
                    return Ok(());
                }
            }
            Err(err) => {
                error!(%err, "failed to send request")
            }
        }
        sleep(Duration::from_secs(3)).await;
    }
}
