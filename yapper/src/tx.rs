use reqwest::{Client, ClientBuilder, Response, Url};
use std::time::Duration;
use timeboost::types::BundleVariant;
use timeboost_crypto::DecryptionScheme;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;

use anyhow::{Context, Result};
use cliquenet::Address;
use timeboost_utils::load_generation::{make_bundle, tps_to_millis};
use tokio::time::interval;
use tracing::{error, warn};

async fn send_transaction(
    client: Client,
    addr: &Address,
    pubkey: &<DecryptionScheme as ThresholdEncScheme>::PublicKey,
) -> Result<Response> {
    let bundle = make_bundle(pubkey)?;

    match bundle {
        BundleVariant::Regular(bundle) => {
            let submision_url = Url::parse(&format!("http://{}/v0/submit-regular", addr))
                .context(format!("parsing {} into a url", addr))?;

            client
                .post(submision_url)
                .body(bincode::serde::encode_to_vec(
                    bundle,
                    bincode::config::standard(),
                )?)
                .send()
                .await
                .context("sending request to the submit-regular endpoint")
        }
        BundleVariant::Priority(signed_priority_bundle) => {
            let submision_url = Url::parse(&format!("http://{}/v0/submit-priority", addr))
                .context(format!("parsing {} into a url", addr))?;
            client
                .post(submision_url)
                .body(bincode::serde::encode_to_vec(
                    signed_priority_bundle,
                    bincode::config::standard(),
                )?)
                .send()
                .await
                .context("sending request to the submit-priority endpoint")
        }
    }
}

pub async fn tx_sender(
    tps: u32,
    addr: Address,
    pubkey: <DecryptionScheme as ThresholdEncScheme>::PublicKey,
) -> Result<()> {
    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(1))
        .build()
        .context("building the reqwest client")?;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(err) = send_transaction(client.clone(), &addr, &pubkey).await {
                    error!(%err, "failed to send transaction");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("sender for {addr} received shutdown signal");
            }
        }
    }
}
