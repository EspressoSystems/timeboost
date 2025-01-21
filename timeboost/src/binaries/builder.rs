use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};
use timeboost::{contracts::committee::CommitteeContract, Timeboost, TimeboostInitializer};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

use clap::Parser;
use timeboost_utils::{types::logging, unsafe_zero_keypair};
use tokio::{signal, sync::watch};
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

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

    /// The id of a node that will start late
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 0)]
    late_start_node_id: u16,

    /// The flag if we want to late start a node
    #[cfg(feature = "until")]
    #[clap(long, short, action = clap::ArgAction::SetTrue)]
    late_start: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let id = NodeId::from(cli.id as u64);

    let keypair = unsafe_zero_keypair(id);

    // Make a new committee contract instance to read the committee config from.
    let committee =
        CommitteeContract::new(id, keypair.public_key(), cli.port, cli.startup_url).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));

    #[cfg(feature = "until")]
    let handle = {
        // Get a host for the public key
        let mut host = committee
            .bootstrap_nodes()
            .iter()
            .find(|b| b.0 == keypair.public_key())
            .map(|b| format!("http://{}", b.1).parse::<reqwest::Url>().unwrap())
            .expect("host to be present");

        // HACK: The port is always 9000 + i in the local setup
        host.set_port(Some(host.port().unwrap() + 1000)).unwrap();

        let task_handle = tokio::spawn(run_until(
            cli.until,
            cli.watchdog_timeout,
            host,
            shutdown_tx.clone(),
        ));
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
        bootstrap_nodes: committee.bootstrap_nodes().into_iter().collect(),
        keypair,
        bind_address,
        shutdown_rx,
    };

    let timeboost = Timeboost::initialize(init).await?;

    tokio::select! {
        _ = timeboost.go(committee.bootstrap_nodes().len()) => {
            #[cfg(feature = "until")]
            {
                tracing::info!("watchdog completed");
                return match handle.await {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(e) => anyhow::bail!("Error: {}", e),
                };
            }

            #[cfg(not(feature = "until"))]
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            shutdown_tx.send(()).expect("the shutdown sender was dropped before the receiver could receive the token");
            Ok(())
        }
    }
}
