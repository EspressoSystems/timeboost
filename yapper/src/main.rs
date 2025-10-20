//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use alloy::providers::ProviderBuilder;
use anyhow::{Result, ensure};
use clap::Parser;
use reqwest::Url;
use timeboost::{
    config::{CommitteeConfig, NodeConfig},
    crypto::prelude::ThresholdEncKey,
};

use timeboost_contract::KeyManager;
use timeboost_utils::types::logging::init_logging;
use timeboost_utils::wait_for_live_peer;
use tokio::signal::{
    ctrl_c,
    unix::{SignalKind, signal},
};
use tracing::{info, warn};

use crate::config::YapperConfig;
use crate::yapper::Yapper;

mod config;
mod yapper;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to folder containing the configs
    ///
    /// The files contain backend urls and public key material.
    #[clap(long, short)]
    config: PathBuf,

    /// Specify how many transactions per second to send to each node
    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// Specify the fraction of encrypted bundles
    #[clap(long, short, default_value_t = 0.5)]
    enc_ratio: f64,

    /// Specify the fraction of priority bundles
    #[clap(long, short, default_value_t = 0.5)]
    prio_ratio: f64,

    /// Nitro node url
    #[clap(long)]
    nitro_url: Option<Url>,

    /// Number of sender addresses on Nitro L2
    #[clap(long, default_value_t = 20)]
    nitro_senders: u32,

    #[clap(long)]
    max_nodes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    ensure!(
        0f64 <= cli.enc_ratio && cli.enc_ratio <= 1f64,
        "enc_ratio must be a fraction between 0 and 1"
    );
    ensure!(
        0f64 <= cli.prio_ratio && cli.prio_ratio <= 1f64,
        "prio_ratio must be a fraction between 0 and 1"
    );

    let mut conf = CommitteeConfig::read(cli.config.join("committee.toml")).await?;
    conf.members.truncate(cli.max_nodes);
    let node = NodeConfig::read(cli.config.join("node_0.toml")).await?;

    let mut addresses = Vec::new();
    for node in conf.members {
        info!("waiting for peer: {}", node.http_api);
        wait_for_live_peer(&node.http_api).await?;
        addresses.push(node.http_api);
    }

    let km_addr = node.chain.parent.key_manager_contract;
    let rpc = node.chain.parent.rpc_url.clone();

    let provider = ProviderBuilder::new().connect_http(rpc.clone());
    let contract = KeyManager::new(km_addr, provider);

    let enc_key =
        ThresholdEncKey::from_bytes(&contract.thresholdEncryptionKey().call().await?.0).ok();

    let config = YapperConfig::builder()
        .addresses(addresses)
        .tps(cli.tps)
        .enc_ratio(cli.enc_ratio)
        .prio_ratio(cli.prio_ratio)
        .maybe_threshold_enc_key(enc_key)
        // nitro-relevant configs
        .maybe_nitro_url(cli.nitro_url)
        .parent_url(rpc)
        .parent_id(node.chain.parent.id)
        .chain_id(node.chain.namespace)
        .bridge_addr(node.chain.parent.ibox_contract)
        .nitro_senders(cli.nitro_senders)
        .build();
    let yapper = Yapper::new(config).await?;

    let mut jh = tokio::spawn(async move { yapper.yap().await });

    let mut signal = signal(SignalKind::terminate()).expect("failed to create sigterm handler");
    tokio::select! {
        _ = ctrl_c() => {
            info!("received Ctrl+C, shutting down yapper...");
        },
        _ = signal.recv() => {
            info!("received sigterm, shutting down yapper...");
        },
        r = &mut jh => {
            warn!("yapping task was terminated, reason: {:?}", r);
        }
    }
    jh.abort();
    Ok(())
}
