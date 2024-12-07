use anyhow::Result;
use timeboost::{
    contracts::committee::{CommitteeBase, CommitteeContract},
    Timeboost, TimeboostInitializer,
};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

use clap::Parser;
use timeboost_networking::network::client::derive_libp2p_multiaddr;
use timeboost_utils::unsafe_zero_keypair;
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

    /// The base to use for the committee config.
    #[clap(long, value_enum, default_value_t = CommitteeBase::Docker)]
    base: CommitteeBase,

    /// The committee size
    #[clap(long, default_value_t = 5)]
    committee_size: u16,

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

    #[cfg(feature = "until")]
    let skip_bootstrap_id = {
        let mut res = None;
        if cli.late_start {
            res = Some(cli.late_start_node_id);
        }
        res
    };

    #[cfg(not(feature = "until"))]
    let skip_bootstrap_id = None;

    // Make a new committee contract instance to read the committee config from.
    let committee = CommitteeContract::new(cli.base, cli.committee_size, skip_bootstrap_id);

    let id = NodeId::from(cli.id as u64);

    let keypair = unsafe_zero_keypair(id);

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let bind_address = &format!("0.0.0.0:{}", cli.port);

    #[cfg(feature = "until")]
    let handle = {
        let task_handle = tokio::spawn(run_until(
            cli.metrics_port,
            cli.until,
            cli.watchdog_timeout,
            matches!(cli.base, CommitteeBase::Docker),
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
        staked_nodes: committee.staked_nodes(),
        keypair,
        bind_address,
        shutdown_rx,
    };

    let timeboost = Timeboost::initialize(init).await?;

    tokio::select! {
        _ = timeboost.go(committee.staked_nodes().len()) => {
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
