use anyhow::Result;
use multiaddr::multiaddr;
use timeboost::{contracts::committee::CommitteeContract, run_timeboost};
use timeboost_core::types::{Keypair, NodeId};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// The port of the node to build.
    #[clap(long)]
    timeboost_port: u16,

    /// The port of the RPC API.
    #[clap(long)]
    timeboost_rpc_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    timeboost_core::logging::init_logging();

    // Make a new committee contract
    let committee = CommitteeContract::new();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let id = NodeId::from(cli.id as u64);

    let keypair = Keypair::zero(id);

    let bind_address = multiaddr!(Ip4([0, 0, 0, 0]), Tcp(cli.timeboost_port));

    run_timeboost(
        id,
        cli.timeboost_port,
        cli.timeboost_rpc_port,
        committee.bootstrap_nodes().into_iter().collect(),
        committee.staked_nodes(),
        keypair,
        bind_address,
    )
    .await
}
