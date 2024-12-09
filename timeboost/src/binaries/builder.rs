use anyhow::Result;
use timeboost::{
    contracts::committee::{CommitteeBase, CommitteeContract},
    run_timeboost,
};
use timeboost_core::types::{Keypair, NodeId};

use clap::Parser;
use timeboost_networking::network::client::derive_libp2p_multiaddr;
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
async fn run_until(port: u16, until: u64, timeout: u64, shutdown_tx: watch::Sender<()>) {
    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(std::time::Duration::from_secs(1)).await;

    let mut timer = sleep(std::time::Duration::from_secs(timeout))
        .fuse()
        .boxed();

    // Deliberately run this on a timeout to avoid a runaway testing scenario.
    loop {
        tokio::select! {
            _ = &mut timer => {
                tracing::error!("watchdog timed out, shutting down");
                shutdown_tx.send(()).expect(
                    "the shutdown sender was dropped before the receiver could receive the token",
                );
                return;
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

                        let timeouts = text
                            .lines()
                            .find(|line| line.starts_with("rounds_timed_out"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);

                        if timeouts >= 10 {
                            tracing::error!("Too many timeouts, shutting down");
                            shutdown_tx.send(()).expect(
                                    "the shutdown sender was dropped before the receiver could receive the token",
                                );
                            return;
                        }

                        if committed_round >= until {
                            tracing::info!("watchdog completed successfully");
                            shutdown_tx.send(()).expect(
                                    "the shutdown sender was dropped before the receiver could receive the token",
                                );
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    timeboost_core::logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    // Make a new committee contract instance to read the committee config from.
    #[cfg(feature = "until")]
    let skip_bootstrap_id = Some(cli.late_start_node_id);
    #[cfg(not(feature = "until"))]
    let skip_bootstrap_id = None;

    let committee = CommitteeContract::new(cli.base, skip_bootstrap_id);

    let id = NodeId::from(cli.id as u64);

    let keypair = Keypair::zero(id);

    let (shutdown_tx, shutdown_rx) = watch::channel(());

    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{}", cli.port)).unwrap();

    #[cfg(feature = "until")]
    {
        tokio::spawn(run_until(
            cli.metrics_port,
            cli.until,
            cli.watchdog_timeout,
            shutdown_tx.clone(),
        ));
        #[cfg(feature = "until")]
        if cli.late_start && cli.id == cli.late_start_node_id {
            tracing::error!("Adding delay before starting node: id: {}", id);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }

    tokio::select! {
        _ = run_timeboost(
            id,
            cli.port,
            cli.rpc_port,
            cli.metrics_port,
            committee.bootstrap_nodes().into_iter().collect(),
            committee.staked_nodes(),
            keypair,
            bind_address,
            shutdown_rx,
        ) => {
            #[cfg(feature = "until")]
            {
                tracing::info!("watchdog completed");
                Ok(())
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
