use anyhow::Result;
use multiaddr::multiaddr;
use timeboost::{contracts::committee::CommitteeContract, run_timeboost};
use timeboost_core::types::{Keypair, NodeId};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u64,

    /// The port of the node to build.
    #[clap(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    timeboost_core::logging::init_logging();

    // Make a new committee contract
    let committee = CommitteeContract::new();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let keypair = Keypair::zero(cli.id);

    let id = NodeId::from(cli.id);

    let port = cli.port.unwrap_or(8000 + cli.id as u16);

    let bind_address = multiaddr!(Ip4([0, 0, 0, 0]), Tcp(port));

    run_timeboost(
        id,
        port,
        committee.bootstrap_nodes().into_iter().collect(),
        committee.staked_nodes(),
        keypair,
        bind_address,
    )
    .await
}
