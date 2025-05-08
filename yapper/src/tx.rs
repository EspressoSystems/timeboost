use futures::future::join_all;
use reqwest::{Client, Url};
use std::time::Duration;
use timeboost::types::BundleVariant;
use timeboost_utils::load_generation::{EncKey, make_bundle, tps_to_millis};
use tokio::time::interval;

use anyhow::{Context, Result};
use cliquenet::Address;
use tracing::{error, warn};

fn setup_clients_and_urls(all_hosts_as_addresses: &[Address]) -> Result<Vec<(Client, Url, Url)>> {
    let mut clients_and_urls = Vec::new();

    for addr in all_hosts_as_addresses {
        // Create a new client for each address
        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .context("building the reqwest client")?;

        let regular_url = Url::parse(&format!("http://{}/v0/submit-regular", addr))
            .with_context(|| format!("parsing {} into a url", addr))?;
        let priority_url = Url::parse(&format!("http://{}/v0/submit-priority", addr))
            .with_context(|| format!("parsing {} into a url", addr))?;

        clients_and_urls.push((client, regular_url, priority_url));
    }

    Ok(clients_and_urls)
}

async fn send_bundle_to_node(
    bundle: &BundleVariant,
    client: &Client,
    regular_url: &str,
    priority_url: &str,
) -> Result<()> {
    let result = match bundle {
        BundleVariant::Regular(bundle) => client
            .post(regular_url)
            .json(&bundle)
            .send()
            .await
            .context("sending request to the submit-regular endpoint"),
        BundleVariant::Priority(signed_priority_bundle) => client
            .post(priority_url)
            .json(&signed_priority_bundle)
            .send()
            .await
            .context("sending request to the submit-priority endpoint"),
    };

    if let Err(err) = result {
        error!(%err, "failed to send transaction");
        return Err(err);
    }
    Ok(())
}

pub async fn yap(addresses: &[Address], pub_key: &EncKey, tps: u32) {
    let client_and_urls =
        setup_clients_and_urls(addresses).expect("failed to setup clients and URLs");

    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // create a bundle for next `interval.tick()`, then send this bundle to each host
        let Ok(b) = make_bundle(pub_key) else {
            warn!("failed to generate bundle");
            continue;
        };

        interval.tick().await;

        let futs = client_and_urls
            .iter()
            .map(|(client, regular_url, priority_url)| async {
                send_bundle_to_node(&b, client, regular_url.as_str(), priority_url.as_str()).await
            });
        let _ = join_all(futs).await;
    }
}
