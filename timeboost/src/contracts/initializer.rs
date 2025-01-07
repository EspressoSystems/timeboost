use anyhow::{Context, Result};
use libp2p_identity::PeerId;
use multisig::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use timeboost_networking::derive_peer_id;
use timeboost_utils::{PeerConfig, ValidatorConfig};
use tokio::time::{sleep, timeout};
use tracing::{error, info};

const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// The response payload for the registrant.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReadyResponse {
    pub node_id: u64,
    pub ip_addr: String,
    pub peer_id: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// The response payload for the network startup.
#[derive(Debug, Deserialize, Serialize)]
pub struct StartResponse {
    pub started: bool,
    pub committee: Vec<ReadyResponse>,
}

pub async fn submit_ready(node_id: u64, kpr: Keypair, url: reqwest::Url) -> Result<()> {
    // First, submit our public key (generated deterministically).
    let client = reqwest::Client::new();

    let peer_id = derive_peer_id::<PublicKey>(&kpr.secret_key())
        .expect("peer id to be generated successfully");
    let peer_id_bytes = bincode::serialize(&peer_id).expect("peer id to serialize successfully");

    let registration = serde_json::to_string(
        &serde_json::json!({ "node_id": node_id, "public_key": kpr.public_key().as_bytes(),  "peer_id": peer_id_bytes }),
    )?;

    timeout(READY_TIMEOUT, async {
        loop {
            match client
                .post(url.clone().join("ready/").expect("valid url"))
                .body(registration.clone())
                .send()
                .await
            {
                Ok(response) => match response.json::<ReadyResponse>().await {
                    Ok(payload) => break payload,
                    Err(e) => {
                        error!(%e, "failed to parse response payload");
                        sleep(std::time::Duration::from_secs(1)).await;
                    }
                },
                Err(e) => {
                    error!(%e, "http request failed");
                    sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
    .await
    .context("response before timeout")?;
    Ok(())
}

pub async fn wait_for_committee(
    kpr: Keypair,
    port: u16,
    url: reqwest::Url,
) -> Result<(
    HashMap<PublicKey, (PeerId, String)>,
    Vec<PeerConfig<PublicKey>>,
)> {
    // Run the timeout again, except waiting for the full system startup
    let committee_data = timeout(READY_TIMEOUT, async {
        loop {
            match reqwest::get(url.clone().join("start/").expect("valid url")).await {
                Ok(response) => match response.json::<StartResponse>().await {
                    Ok(payload) => {
                        if payload.started {
                            break payload;
                        }

                        // Otherwise, wait a sec before checking again
                        sleep(std::time::Duration::from_secs(1)).await;
                    }
                    Err(e) => {
                        error!(%e, "failed to parse response payload");
                        sleep(std::time::Duration::from_secs(1)).await;
                    }
                },
                Err(e) => {
                    error!(%e, "http request failed");
                    sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
    .await
    .context("commitee to be created before timeout")?;

    let mut bootstrap_nodes = HashMap::new();
    let mut staked_nodes = vec![];
    for c in committee_data.committee.into_iter() {
        let remote_bind_addr = format!("{}:{}", c.ip_addr, port);
        info!("{remote_bind_addr}");
        let cfg =
            ValidatorConfig::<PublicKey>::generated_from_seed_indexed([0; 32], c.node_id, 1, false);
        bootstrap_nodes.insert(
            kpr.public_key(),
            (
                bincode::deserialize::<PeerId>(&c.peer_id)
                    .expect("peer id to deserialize successfully"),
                remote_bind_addr,
            ),
        );
        staked_nodes.push(cfg.public_config());
    }

    Ok((bootstrap_nodes, staked_nodes))
}
