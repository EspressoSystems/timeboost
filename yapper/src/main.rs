//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use anyhow::{Result, bail, ensure};
use clap::Parser;
use multisig::{CommitteeId, rand::seq::IndexedRandom};
use reqwest::Url;
use timeboost::config::{ConfigService, HTTP_API_PORT_OFFSET, NodeConfig, config_service};

use timeboost_utils::types::logging::init_logging;
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
    /// Path to a node config file.
    #[clap(long, short)]
    nodes: PathBuf,

    #[clap(long)]
    committee: CommitteeId,

    #[clap(long)]
    config_service: String,

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

    let mut service = config_service(&cli.config_service).await?;

    let Some(committee) = service.get(cli.committee).await? else {
        bail!("no committee found for id {}", cli.committee)
    };

    let Some(member) = committee.members.choose(&mut rand::rng()) else {
        bail!("committee {} has no members", cli.committee)
    };

    let node = NodeConfig::read(cli.nodes.join(format!("{}.toml", member.signing_key))).await?;

    let rpc = node.chain.rpc_url.clone();

    let config = YapperConfig::builder()
        .addresses(
            committee
                .members
                .iter()
                .map(|m| m.address.clone().with_offset(HTTP_API_PORT_OFFSET))
                .collect(),
        )
        .tps(cli.tps)
        .enc_ratio(cli.enc_ratio)
        .prio_ratio(cli.prio_ratio)
        .maybe_nitro_url(cli.nitro_url)
        .parent_url(rpc)
        .parent_id(node.chain.id)
        .chain_id(node.espresso.namespace)
        .bridge_addr(node.chain.inbox_contract)
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
