pub mod enc_key;
pub mod load_generation;
pub mod types;
pub mod until;

use std::io;
use std::{fmt::Display, path::Path, time::Duration};

use cliquenet::Address;
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::time::sleep;
use tracing::{error, info};

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

pub async fn write_csv<A, B, P, I>(path: P, hdrs: (&str, &str), vals: I) -> io::Result<()>
where
    A: Display,
    B: Display,
    P: AsRef<Path>,
    I: IntoIterator<Item = (A, B)>,
{
    let mut csv = vec![format!("{},{}", hdrs.0, hdrs.1)];
    csv.extend(vals.into_iter().map(|(a, b)| format!("{a},{b}")));
    let mut w = BufWriter::new(fs::File::create(path).await?);
    w.write_all(csv.join("\n").as_bytes()).await?;
    w.flush().await
}
