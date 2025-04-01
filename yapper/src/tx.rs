use std::time::Duration;
use url::Url;

use anyhow::{Context, Result};
use cliquenet::Address;
use timeboost_utils::load_generation::tps_to_millis;
use tokio::time::interval;
use tracing::warn;

pub async fn tx_sender(tps: u32, addr: Address) -> Result<()> {
    let submision_url = Url::parse(&format!("http://{}/v0/submit", addr.to_string()))
        .context(format!("parsing {} into a url", addr.to_string()))?;
    let mut interval = interval(Duration::from_millis(tps_to_millis(tps)));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Send tx
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("sender for {addr} received shutdown signal");
            }
        }
    }
}
