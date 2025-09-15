//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use anyhow::{Context, Result};

use clap::Parser;
use reqwest::Url;
use timeboost::config::CommitteeConfig;
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
    /// Path to file containing the committee member's public info.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// Specify how many transactions per second to send to each node
    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// Chain id for l2 chain
    /// default: https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
    #[clap(long, default_value_t = 412346)]
    chain_id: u64,

    /// Nitro node url.
    #[clap(long)]
    nitro_url: Option<Url>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    info!("starting yapper");
    let cli = Cli::parse();

    // Unpack the keyset file which has the urls
    let keyset = CommitteeConfig::read(&cli.keyset_file)
        .await
        .with_context(|| format!("opening the keyfile at path {:?}", cli.keyset_file))?;

    let mut addresses = Vec::new();
    for node in keyset.members {
        info!("waiting for peer: {}", node.http_api);
        wait_for_live_peer(&node.http_api).await?;
        addresses.push(node.http_api);
    }

    let config = YapperConfig::builder()
        .addresses(addresses)
        .tps(cli.tps)
        .maybe_nitro_url(cli.nitro_url)
        .chain_id(cli.chain_id)
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
