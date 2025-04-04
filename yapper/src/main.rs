//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cliquenet::Address;

use clap::Parser;
use multisig::Keypair;
use timeboost::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::types::logging::init_logging;
use tracing::error;
use tx::tx_sender;

mod tx;

#[derive(Parser, Debug)]
struct Cli {
    /// The number of nodes that are being run in this instance.
    #[clap(long)]
    nodes: Option<usize>,

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

    let cli = Cli::parse();

    // The total number of nodes that are running.
    let num = cli.nodes.unwrap_or(4);

    // Unpack the keyset file which has the urls
    let keyset = KeysetConfig::read_keyset(&cli.keyset_file).context(format!(
        "opening the keyfile at path {}",
        cli.keyset_file.to_string_lossy(),
    ))?;

    // TODO: make this selection a helper.
    // Rust is *really* picky about mixing iterators, so we just erase the type.
    let peer_host_iter: Box<dyn Iterator<Item = &_>> = if cli.multi_region {
        // The number of nodes to take from the group. The layout of the nodes
        // is such that (in the cloud) each region
        // continues sequentially from the prior region.
        // So if us-east-2 has nodes 0, 1, 2, 3 and us-west-2 has nodes
        // 4, 5, 6, 7, then we need to offset this otherwise we'd
        // attribute us-east-2 nodes to us-west-2.
        let take_from_group = num / 4;

        Box::new(
            keyset
                .keyset()
                .chunks(4)
                .flat_map(move |v| v.iter().take(take_from_group)),
        )
    } else {
        // Fallback behavior for multi regions, we just take the first n nodes if we're running on a single region or all
        // on the same host.
        Box::new(keyset.keyset().iter().take(num))
    };

    let mut all_hosts_as_addresses = Vec::new();
    for peer_host in peer_host_iter {
        let mut raw_url_split = peer_host.url.splitn(3, ":");
        let host = raw_url_split.next().context(format!(
            "fetching host from peer host url {}",
            peer_host.url
        ))?;

        // This is a hack
        let port: u16 = raw_url_split
            .next()
            .context(format!(
                "extracting port from peer host url {}",
                peer_host.url
            ))?
            .parse::<u16>()
            .context("parsing port into u16")?
            + 800u16;
        let address = Address::from((host, port));

        // Wait for the peeer to come online so we know it's valid.
        wait_for_live_peer(address.clone()).await?;

        all_hosts_as_addresses.push(address);
    }

    // Spawn a new thread per host and let em rip.
    for address in all_hosts_as_addresses {
        tokio::spawn(async move {
            if let Err(err) = tx_sender(cli.tps, address /*KEY */).await {
                error!(%err, "tx sender failed");
            }
        });
    }

    Ok(())
}
