use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};
use timeboost::{contracts::committee::CommitteeContract, Timeboost, TimeboostInitializer};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

use clap::Parser;
use local_ip_address::local_ip;
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

    /// The ip address of the startup coordinator
    #[clap(long, default_value = "http://localhost:7200/")]
    startup_url: reqwest::Url,

    /// The broadcasted ip of this node, if unset, it defaults to [`local_ip`].
    #[clap(long)]
    broadcast_ip: Option<SocketAddr>,

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

    /// The ip address of the nitro node for gas estimations.
    #[clap(long)]
    nitro_node_url: Option<reqwest::Url>,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let id = NodeId::from(cli.id as u64);

    let keypair = unsafe_zero_keypair(id);

    // The self-reported host of this machine
    let broadcast_ip = match cli.broadcast_ip {
        Some(host) => host,
        None => format!("{}:{}", local_ip()?, cli.port).parse()?,
    };

    // Make a new committee contract instance to read the committee config from.
    let committee =
        CommitteeContract::new(id, broadcast_ip, keypair.public_key(), cli.startup_url).await;

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));

    #[cfg(feature = "until")]
    let handle = {
        // Get a host for the public key
        let mut host = committee
            .peers()
            .iter()
            .find(|b| b.0 == keypair.public_key())
            .map(|b| format!("http://{}", b.1).parse::<reqwest::Url>().unwrap())
            .expect("host to be present");

        // HACK: The port is always 9000 + i in the local setup
        host.set_port(Some(host.port().unwrap() + 1000)).unwrap();

        let task_handle = tokio::spawn(run_until(cli.until, cli.watchdog_timeout, host));
        if cli.late_start && cli.id == cli.late_start_node_id {
            tracing::warn!("Adding delay before starting node: id: {}", id);
            tokio::time::sleep(std::time::Duration::from_secs(LATE_START_DELAY_SECS)).await;
        }
        task_handle
    };

    let init = TimeboostInitializer {
        id,
        rpc_port: cli.rpc_port,
        metrics_port: cli.metrics_port,
        peers: committee.peers().into_iter().collect(),
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
        _ = timeboost.go(committee.peers().len(), cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
        }
    }
    #[cfg(not(feature = "until"))]
    tokio::select! {
        _ = timeboost.go(committee.peers().len(), cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
        }
    }
    Ok(())
}
