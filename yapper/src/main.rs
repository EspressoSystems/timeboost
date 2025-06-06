//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use anyhow::{Context, Result};

use clap::Parser;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::select_peer_hosts;
use timeboost_utils::types::logging::init_logging;
use tokio::signal::{
    ctrl_c,
    unix::{SignalKind, signal},
};
use tracing::{info, warn};
use tx::yap;

mod tx;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// Specify how many transactions per second to send to each node
    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// Specify how to read the configuration file.
    #[clap(long, default_value_t = false)]
    multi_region: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    info!("starting yapper");
    let cli = Cli::parse();

    // Unpack the keyset file which has the urls
    let keyset = KeysetConfig::read_keyset(&cli.keyset_file)
        .with_context(|| format!("opening the keyfile at path {:?}", cli.keyset_file,))?;

    let nodes = select_peer_hosts(&keyset.keyset, cli.multi_region);

    let mut addresses = Vec::new();
    for node in nodes {
        info!("waiting for peer: {}", node.sailfish_address);
        let mut addr = node.sailfish_address.clone();
        wait_for_live_peer(addr.clone()).await?;
        addr.set_port(800 + addr.port());
        addresses.push(addr);
    }

    let mut jh =
        tokio::spawn(async move { yap(&addresses, &keyset.dec_keyset.pubkey, cli.tps).await });

    let mut signal = signal(SignalKind::terminate()).expect("failed to create sigterm handler");
    tokio::select! {
        _ = ctrl_c() => {
            info!("received Ctrl+C, shutting down yapper...");
        },
        _ = signal.recv() => {
            info!("received sigterm, shutting down yapper...");
        },
        r = &mut jh => {
            warn!("yapping task was terminated, reason: {:?}", r);
        }
    }
    jh.abort();
    Ok(())
}
