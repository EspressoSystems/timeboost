use anyhow::{ensure, Context, Result};
use multisig::PublicKey;
use serde_json::from_str;
use std::fs;
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use timeboost::{Timeboost, TimeboostInitializer};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

use clap::Parser;
use timeboost_utils::{types::logging, unsafe_zero_keypair};
use tokio::signal;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// The port of the node to build.
    #[clap(long)]
    port: u16,

    /// The port of the RPC API.
    #[clap(long)]
    rpc_port: u16,

    /// The port of the metrics server.
    #[clap(long)]
    metrics_port: u16,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

    /// The id of a node that will start late.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 0)]
    late_start_node_id: u16,

    /// The flag if we want to late start a node
    #[cfg(feature = "until")]
    #[clap(long, short, action = clap::ArgAction::SetTrue)]
    late_start: bool,

    /// NON PRODUCTION: An internal load generator will generate at a rate of X per second.
    /// Set this to 0 for no load generation.
    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// NON PRODUCTION: A deterministic key generator is used for local/cloud testing. The format
    /// will just be a list of addresses since keys are deterministic. So if we have 5 nodes like in
    /// docker it'll just be
    /// [
    ///     "172.20.0.2",
    ///     "172.20.0.3",
    ///     "172.20.0.4",
    ///     "172.20.0.5",
    ///     "172.20.0.6"
    /// ]
    #[clap(long)]
    keyfile: PathBuf,

    /// The ip address of the nitro node for gas estimations.
    #[clap(long)]
    nitro_node_url: Option<reqwest::Url>,
}

pub fn read_test_config(path: PathBuf) -> Result<Vec<String>> {
    ensure!(path.exists(), "File not found: {:?}", path);
    let data = fs::read_to_string(&path).context("Failed to read file")?;
    let vec: Vec<String> = from_str(&data).context("Failed to parse JSON")?;
    Ok(vec)
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let id = NodeId::from(cli.id as u64);

    let keypair = unsafe_zero_keypair(id);

    let peer_hosts = read_test_config(cli.keyfile).expect("keyfile to exist and be valid");

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = peer_hosts
        .iter()
        .map(|ph| format!("http://{}", ph).parse().unwrap())
        .collect();

    let peer_hosts_and_keys = peer_hosts
        .into_iter()
        .enumerate()
        .map(|(peer_id, peer_host)| {
            (
                unsafe_zero_keypair(peer_id as u64).public_key(),
                peer_host.parse().expect("valid socket addr"),
            )
        })
        .collect::<Vec<(PublicKey, SocketAddr)>>();

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));

    #[cfg(feature = "until")]
    let handle = {
        ensure!(peer_urls.len() >= usize::from(cli.id), "Not enough peers");
        let mut host = peer_urls[usize::from(cli.id)].clone();

        // HACK: The port is always 9000 + i in the local setup
        host.set_port(Some(host.port().unwrap() + 1000)).unwrap();

        let task_handle = tokio::spawn(run_until(cli.until, cli.watchdog_timeout, host));
        if cli.late_start && cli.id == cli.late_start_node_id {
            tracing::warn!("Adding delay before starting node: id: {}", id);
            tokio::time::sleep(std::time::Duration::from_secs(LATE_START_DELAY_SECS)).await;
        }
        task_handle
    };

    let committee_size = peer_hosts_and_keys.len();
    let init = TimeboostInitializer {
        id,
        rpc_port: cli.rpc_port,
        metrics_port: cli.metrics_port,
        peers: peer_hosts_and_keys,
        keypair,
        bind_address,
        nitro_url: cli.nitro_node_url,
    };

    let timeboost = Timeboost::initialize(init).await?;

    #[cfg(feature = "until")]
    tokio::select! {
        res = handle => {
            tracing::info!("watchdog completed");
            return match res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => anyhow::bail!("Error: {}", e),
            };
        },
        _ = timeboost.go(committee_size, cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
        }
    }
    #[cfg(not(feature = "until"))]
    tokio::select! {
        _ = timeboost.go(committee_size, cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
        }
    }
    Ok(())
}
