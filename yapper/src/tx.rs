use futures::future::join_all;
use reqwest::{Client, Url};
use std::time::Duration;
use timeboost::types::BundleVariant;
use timeboost_crypto::prelude::ThresholdEncKey;
use timeboost_utils::load_generation::{make_bundle, tps_to_millis};
use tokio::time::interval;

use anyhow::{Context, Result};
use cliquenet::Address;
use tracing::warn;

fn setup_urls(all_hosts_as_addresses: &[Address]) -> Result<Vec<(Url, Url, Url)>> {
    let mut urls = Vec::new();

    for addr in all_hosts_as_addresses {
        let regular_url = Url::parse(&format!("http://{addr}/v0/submit-regular"))
            .with_context(|| format!("parsing {addr} into a url"))?;
        let priority_url = Url::parse(&format!("http://{addr}/v0/submit-priority"))
            .with_context(|| format!("parsing {addr} into a url"))?;
        let enckey_url = Url::parse(&format!("http://{addr}/v0/enckey"))
            .with_context(|| format!("parsing {addr} into a url"))?;

        urls.push((regular_url, priority_url, enckey_url));
    }

    Ok(urls)
}

async fn send_bundle_to_node(
    bundle: &BundleVariant,
    client: &Client,
    regular_url: &Url,
    priority_url: &Url,
) {
    let result = match bundle {
        BundleVariant::Regular(bundle) => {
            client.post(regular_url.clone()).json(&bundle).send().await
        }
        BundleVariant::Priority(signed_priority_bundle) => {
            client
                .post(priority_url.clone())
                .json(&signed_priority_bundle)
                .send()
                .await
        }
        _ => {
            warn!("Unsupported bundle variant");
            return;
        }
    };

    match result {
        Ok(response) => {
            if !response.status().is_success() {
                warn!("response status: {}", response.status());
            }
        }
        Err(err) => {
            warn!(%err, "failed to send bundle");
        }
    }
}

async fn fetch_encryption_key(client: &Client, enckey_url: &Url) -> Option<ThresholdEncKey> {
    let response = match client.post(enckey_url.clone()).send().await {
        Ok(response) => response,
        Err(err) => {
            warn!(%err, "failed to request encryption key");
            return None;
        }
    };

    if !response.status().is_success() {
        warn!("enckey request failed with status: {}", response.status());
        return None;
    }

    match response.json::<Option<ThresholdEncKey>>().await {
        Ok(enc_key) => enc_key,
        Err(err) => {
            warn!(%err, "failed to parse encryption key response");
            None
        }
    }
}

pub async fn yap(addresses: &[Address], tps: u32) -> Result<()> {
    let c = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let urls = setup_urls(addresses)?;

    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut enc_key = None;
    let enckey_url = &urls.first().expect("urls shouldn't be empty").2;
    loop {
        if enc_key.is_none() {
            enc_key = fetch_encryption_key(&c, enckey_url).await;
        }

        // create a bundle for next `interval.tick()`, then send this bundle to each node
        let Ok(b) = make_bundle(enc_key.as_ref()) else {
            warn!("failed to generate bundle");
            continue;
        };

        interval.tick().await;

        join_all(urls.iter().map(|(regular_url, priority_url, _)| async {
            send_bundle_to_node(&b, &c, regular_url, priority_url).await
        }))
        .await;
    }
}
