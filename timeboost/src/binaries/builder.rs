use anyhow::{bail, Result};
use sailfish::sailfish::ShutdownToken;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    timeboost_core::logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    // Make a new committee contract instance to read the committee config from.
    let committee = CommitteeContract::new(cli.base);

    let id = NodeId::from(cli.id as u64);

    let keypair = Keypair::zero(id);

    let (shutdown_tx, shutdown_rx) = watch::channel(ShutdownToken::new());

    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{}", cli.port)).unwrap();
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
            bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            shutdown_tx.send(ShutdownToken::new()).expect("The shutdown sender was dropped before the receiver could receive the token");
            return Ok(());
        }
    }
}
