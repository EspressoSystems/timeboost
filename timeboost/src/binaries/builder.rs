use anyhow::Result;
use timeboost::{
    contracts::committee::{CommitteeBase, CommitteeContract},
    Timeboost, TimeboostInitializer,
};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;

use clap::Parser;
use timeboost_networking::network::client::derive_libp2p_multiaddr;
use timeboost_utils::unsafe_zero_keypair;
use tokio::{signal, sync::watch};
use tracing::warn;

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

    /// The base to use for the committee config.
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

    /// Do we want to late start a node
    #[cfg(feature = "until")]
    #[clap(long, short, action = clap::ArgAction::SetTrue)]
    late_start: bool,
}

#[cfg(feature = "until")]
async fn run_until(
    port: u16,
    until: u64,
    timeout: u64,
    shutdown_tx: watch::Sender<()>,
    mut shutdown_rx: watch::Receiver<()>,
) -> Result<()> {
    use std::time::{Duration, Instant};

    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(std::time::Duration::from_secs(1)).await;

    let mut timer = sleep(std::time::Duration::from_secs(timeout))
        .fuse()
        .boxed();

    let mut last_committed = 0;
    let mut last_committed_time = Instant::now();

    // Deliberately run this on a timeout to avoid a runaway testing scenario.
    loop {
        tokio::select! { biased;
            _ = &mut timer => {
                tracing::error!("watchdog timed out, shutting down");
                shutdown_tx.send(()).expect(
                    "the shutdown sender was dropped before the receiver could receive the token",
                );
                anyhow::bail!("Watchdog timeout");
            }
            result = shutdown_rx.changed() => {
                tracing::error!("received shutdown");
                result.expect("the shutdown sender was dropped before the receiver could receive the token");
                anyhow::bail!("Shutdown received");
            }
            resp = reqwest::get(format!("http://localhost:{}/status/metrics", port)) => {
                if let Ok(resp) = resp {
                    if let Ok(text) = resp.text().await {
                        let committed_round = text
                            .lines()
                            .find(|line| line.starts_with("committed_round"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);

                        if committed_round > 0 && committed_round % 10 == 0 {
                            tracing::info!("committed_round: {}", committed_round);
                        }

                        let now = Instant::now();
                        if committed_round == last_committed && now.saturating_duration_since(last_committed_time) > Duration::from_secs(30) {
                            shutdown_tx.send(()).expect(
                                "the shutdown sender was dropped before the receiver could receive the token",
                            );
                            anyhow::bail!("Node stuck on round for more than 30 seconds")
                        } else if committed_round > last_committed {
                            last_committed = committed_round;
                            last_committed_time = now;
                        }

                        let timeouts = text
                            .lines()
                            .find(|line| line.starts_with("rounds_timed_out"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);

                        if timeouts >= 15 {
                            shutdown_tx.send(()).expect(
                                "the shutdown sender was dropped before the receiver could receive the token",
                            );
                            anyhow::bail!("Node timed out too many rounds")
                        }

                        if committed_round >= until {
                            tracing::info!("watchdog completed successfully");
                            shutdown_tx.send(()).expect(
                                    "the shutdown sender was dropped before the receiver could receive the token",
                                );
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    timeboost_core::logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    // Make a new committee contract instance to read the committee config from.
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

    let committee = CommitteeContract::new(cli.base, cli.committee_size, skip_bootstrap_id);

    let id = NodeId::from(cli.id as u64);

    let keypair = unsafe_zero_keypair(id);

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{}", cli.port)).unwrap();

    #[cfg(feature = "until")]
    let handle = {
        let h = tokio::spawn(run_until(
            cli.metrics_port,
            cli.until,
            cli.watchdog_timeout,
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        ));
        if cli.late_start && cli.id == cli.late_start_node_id {
            tracing::error!("Adding delay before starting node: id: {}", id);
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
        tracing::error!("Starting node id: {}", id);
        h
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
            tracing::info!("watchdog completed");

            #[cfg(not(feature = "until"))]
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            shutdown_tx.send(()).expect("the shutdown sender was dropped before the receiver could receive the token");
            return Ok(());
        }
    }

    #[cfg(feature = "until")]
    {
        let res = handle.await;
        return match res {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => anyhow::bail!("Error: {}", e),
        };
    }
}
