use futures::future::join_all;
use reqwest::{Client, Url};
use std::time::Duration;
use timeboost::types::BundleVariant;
use timeboost_utils::load_generation::{EncKey, make_bundle, tps_to_millis};
use tokio::time::interval;

use anyhow::{Context, Result};
use cliquenet::Address;
use tracing::warn;

fn setup_urls(all_hosts_as_addresses: &[Address]) -> Result<Vec<(Url, Url)>> {
    let mut urls = Vec::new();

    for addr in all_hosts_as_addresses {
        let regular_url = Url::parse(&format!("http://{}/v0/submit-regular", addr))
            .with_context(|| format!("parsing {} into a url", addr))?;
        let priority_url = Url::parse(&format!("http://{}/v0/submit-priority", addr))
            .with_context(|| format!("parsing {} into a url", addr))?;

        urls.push((regular_url, priority_url));
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

pub async fn yap(addresses: &[Address], pub_key: &EncKey, tps: u32) -> Result<()> {
    let c = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let urls = setup_urls(addresses)?;

    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // create a bundle for next `interval.tick()`, then send this bundle to each node
        let Ok(b) = make_bundle(pub_key) else {
            warn!("failed to generate bundle");
            continue;
        };

        interval.tick().await;

        join_all(urls.iter().map(|(regular_url, priority_url)| async {
            send_bundle_to_node(&b, &c, regular_url, priority_url).await
        }))
        .await;
    }
}
