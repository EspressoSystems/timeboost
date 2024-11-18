use std::net::{IpAddr, ToSocketAddrs};

use anyhow::{anyhow, Context, Result};
use multiaddr::Multiaddr;
use sailfish::sailfish::ShutdownToken;
use timeboost::{contracts::committee::CommitteeContract, run_timeboost};
use timeboost_core::types::{Keypair, NodeId};

use clap::Parser;
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
}

pub fn derive_libp2p_multiaddr(addr: &String) -> anyhow::Result<Multiaddr> {
    // Split the address into the host and port parts
    let (host, port) = match addr.rfind(':') {
        Some(idx) => (&addr[..idx], &addr[idx + 1..]),
        None => return Err(anyhow!("Invalid address format, no port supplied")),
    };

    // Try parsing the host as an IP address
    let ip = host.parse::<IpAddr>();

    // Conditionally build the multiaddr string
    let multiaddr_string = match ip {
        Ok(IpAddr::V4(ip)) => format!("/ip4/{ip}/udp/{port}/quic-v1"),
        Ok(IpAddr::V6(ip)) => format!("/ip6/{ip}/udp/{port}/quic-v1"),
        Err(_) => {
            // Try resolving the host. If it fails, continue but warn the user
            let lookup_result = addr.to_socket_addrs();

            // See if the lookup failed
            let failed = lookup_result
                .map(|result| result.collect::<Vec<_>>().is_empty())
                .unwrap_or(true);

            // If it did, warn the user
            if failed {
                warn!(
                    "Failed to resolve domain name {}, assuming it has not yet been provisioned",
                    host
                );
            }

            format!("/dns/{host}/udp/{port}/quic-v1")
        }
    };

    // Convert the multiaddr string to a `Multiaddr`
    multiaddr_string.parse().with_context(|| {
        format!("Failed to convert Multiaddr string to Multiaddr: {multiaddr_string}",)
    })
}

#[tokio::main]
async fn main() -> Result<ShutdownToken> {
    timeboost_core::logging::init_logging();

    // Make a new committee contract
    let committee = CommitteeContract::new();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    let id = NodeId::from(cli.id as u64);

    let keypair = Keypair::zero(id);

    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{}", cli.port)).unwrap();

    run_timeboost(
        id,
        cli.port,
        cli.rpc_port,
        committee.bootstrap_nodes().into_iter().collect(),
        committee.staked_nodes(),
        keypair,
        bind_address,
    )
    .await
}
