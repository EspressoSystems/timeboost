use std::net::SocketAddr;

use anyhow::Result;
use multisig::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use timeboost_utils::{PeerConfig, ValidatorConfig};
use tokio::time::sleep;
use tracing::{error, info};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// The response payload for the registrant.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReadyResponse {
    pub node_id: u64,
    pub ip_addr: SocketAddr,
    pub public_key: Vec<u8>,
}

/// The response payload for the network startup.
#[derive(Debug, Deserialize, Serialize)]
pub struct StartResponse {
    pub started: bool,
    pub committee: Vec<ReadyResponse>,
}

pub async fn submit_ready(
    node_id: u64,
    node_port: u16,
    kpr: Keypair,
    url: reqwest::Url,
) -> Result<()> {
    // First, submit our public key (generated deterministically).
    let client = reqwest::Client::new();

    let registration = serde_json::to_string(
        &serde_json::json!({ "node_id": node_id, "public_key": kpr.public_key().as_bytes(), "node_port": node_port }),
    )?;

    loop {
        match client
            .post(url.clone().join("ready/").expect("valid url"))
            .body(registration.clone())
            .send()
            .await
        {
            Ok(response) => match response.json::<ReadyResponse>().await {
                Ok(_) => break,
                Err(e) => {
                    error!(%e, "failed to parse response payload");
                    sleep(RETRY_INTERVAL).await;
                }
            },
            Err(e) => {
                error!(%e, "http request failed");
                sleep(RETRY_INTERVAL).await;
            }
        }
    }

    Ok(())
}

pub async fn wait_for_committee(
    url: reqwest::Url,
) -> Result<(HashMap<PublicKey, SocketAddr>, Vec<PeerConfig<PublicKey>>)> {
    // Run the timeout again, except waiting for the full system startup
    let committee_data = loop {
        match reqwest::get(url.clone().join("start/").expect("valid url")).await {
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
                error!(%e, "http request failed");
                sleep(RETRY_INTERVAL).await;
            }
        }
    };

    let mut bootstrap_nodes = HashMap::new();
    let mut staked_nodes = vec![];
    for c in committee_data.committee.into_iter() {
        info!("{}", c.ip_addr);
        let cfg =
            ValidatorConfig::<PublicKey>::generated_from_seed_indexed([0; 32], c.node_id, 1, false);
        bootstrap_nodes.insert(
            PublicKey::try_from(c.public_key.as_slice())
                .expect("public key to deserialize successfully"),
            c.ip_addr,
        );
        staked_nodes.push(cfg.public_config());
    }

    Ok((bootstrap_nodes, staked_nodes))
}
