use std::net::SocketAddr;

use anyhow::Result;
use multisig::PublicKey;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use tracing::error;

const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The request payload for the registrant.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReadyRequest {
    pub node_id: u64,
    pub node_host: SocketAddr,
    pub public_key: PublicKey,
}

/// The response payload for the registrant.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReadyResponse {
    pub node_id: u64,
    pub public_key: PublicKey,
    pub ip_addr: SocketAddr,
}

/// The response payload for the network startup.
#[derive(Debug, Deserialize, Serialize)]
pub struct StartResponse {
    pub started: bool,
    pub committee: Vec<ReadyResponse>,
}

pub async fn submit_ready(
    node_id: u64,
    node_host: SocketAddr,
    public_key: PublicKey,
    url: Url,
) -> Result<()> {
    // First, submit our public key (generated deterministically).
    let client = reqwest::Client::new();

    let req = ReadyRequest {
        node_id,
        public_key,
        node_host,
    };
    loop {
        let Ok(ready_url) = url.clone().join("ready/") else {
            error!("URL {url} could not join with `ready/`");
            panic!("invalid url");
        };

        match client.post(ready_url.clone()).json(&req).send().await {
            Ok(response) => match response.json::<ReadyResponse>().await {
                Ok(_) => break,
                Err(e) => {
                    error!(%e, "failed to parse response payload");
                    sleep(RETRY_INTERVAL).await;
                }
            },
            Err(e) => {
                error!(%e, "http request to {ready_url} failed");
                sleep(RETRY_INTERVAL).await;
            }
        }
    }

    Ok(())
}

pub async fn wait_for_committee(url: reqwest::Url) -> Result<Vec<(PublicKey, SocketAddr)>> {
    // Run the timeout again, except waiting for the full system startup
    let committee_data = loop {
        let Ok(start_url) = url.clone().join("start/") else {
            error!("URL {url} could not join with `start/`");
            panic!("invalid url");
        };
        match reqwest::get(start_url.clone()).await {
            Ok(response) => match response.json::<StartResponse>().await {
                Ok(payload) => {
                    if payload.started {
                        break payload;
                    }

                    // Otherwise, wait a sec before checking again
                    sleep(RETRY_INTERVAL).await;
                }
                Err(e) => {
                    error!(%e, "failed to parse response payload");
                    sleep(RETRY_INTERVAL).await;
                }
            },
            Err(e) => {
                error!(%e, "http request to {start_url} failed");
                sleep(RETRY_INTERVAL).await;
            }
        }
    };

    let mut bootstrap_nodes = Vec::new();
    for c in committee_data.committee.into_iter() {
        bootstrap_nodes.push((c.public_key, c.ip_addr));
    }

    Ok(bootstrap_nodes)
}
