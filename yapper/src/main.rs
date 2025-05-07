//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cliquenet::Address;

use clap::Parser;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::select_peer_hosts;
use timeboost_utils::types::logging::init_logging;
use tracing::{error, info};
use tx::tx_sender;

mod tx;

#[derive(Parser, Debug)]
struct Cli {
    /// The number of nodes that are being run in this instance.
    #[clap(long)]
    nodes: usize,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// Specify how to read the configuration file.
    #[clap(long, default_value_t = false)]
    multi_region: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    info!("Starting yapper");
    let cli = Cli::parse();

    // Unpack the keyset file which has the urls
    let keyset = KeysetConfig::read_keyset(&cli.keyset_file).context(format!(
        "opening the keyfile at path {}",
        cli.keyset_file.to_string_lossy(),
    ))?;

    // TODO: make this selection a helper.
    let peer_host_iter = select_peer_hosts(keyset.keyset(), cli.nodes, cli.multi_region);

    let mut all_hosts_as_addresses = Vec::new();
    for peer_host in peer_host_iter {
        let mut raw_url_split = peer_host.sailfish_url.splitn(3, ":");
        let host = raw_url_split.next().context(format!(
            "fetching host from peer host url {}",
            peer_host.sailfish_url
        ))?;

        // This is a hack
        let port: u16 = raw_url_split
            .next()
            .context(format!(
                "extracting port from peer host url {}",
                peer_host.sailfish_url
            ))?
            .parse::<u16>()
            .context("parsing port into u16")?;
        let mut address = Address::from((host, port));

        // Wait for the peeer to come online so we know it's valid.
        wait_for_live_peer(address.clone()).await?;
        address.set_port(800 + address.port());
        all_hosts_as_addresses.push(address);
    }

    let mut jhs = Vec::new();
    // Spawn a new thread per host and let em rip.
    for address in all_hosts_as_addresses {
        jhs.push(tokio::spawn({
            let keyset = keyset.clone();
            let pubkey = keyset.dec_keyset().pubkey()?;
            async move {
                if let Err(err) = tx_sender(cli.tps, address, pubkey).await {
                    error!(%err, "tx sender failed");
                }
            }
        }));
    }

    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down yapper...");
        },
        _ = signal.recv() => {
            info!("Received SIGTERM, shutting down yapper...");
        },
    }
    for jh in jhs {
        jh.abort();
    }
    Ok(())
}
