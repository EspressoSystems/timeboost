use reqwest::{Client, ClientBuilder, Url};
use std::time::Duration;
use timeboost_crypto::DecryptionScheme;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;

use anyhow::{Context, Result};
use cliquenet::Address;
use timeboost_utils::load_generation::{make_bundle, tps_to_millis};
use tokio::time::interval;
use tracing::{error, warn};

async fn send_transaction(
    addr: &Address,
    pubkey: &<DecryptionScheme as ThresholdEncScheme>::PublicKey,
) -> Result<()> {
    let submision_url = Url::parse(&format!("http://{}/v0/submit", addr.to_string()))
        .context(format!("parsing {} into a url", addr.to_string()))?;
    let bundle = make_bundle(pubkey)?;

    Ok(())
}

pub async fn tx_sender(
    tps: u32,
    addr: Address,
    pubkey: <DecryptionScheme as ThresholdEncScheme>::PublicKey,
) -> Result<()> {
    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    let client = ClientBuilder::new().timeout(Duration::from_secs(1)).build();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(err) = send_transaction(&addr, &pubkey).await {
                    error!(%err, "failed to send transaction");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("sender for {addr} received shutdown signal");
            }
        }
    }
}
