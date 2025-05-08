//! The Yapper emulates user wallet software. The idea is to multicast
//! a transaction to the entire committee. The yapper... yaps about its
//! transactions to everyone. The transactions are unstructured bytes, but
//! they're the *same* unstructured bytes for each node in the committee
//! due to the requirement of Timeboost.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use cliquenet::Address;

use clap::Parser;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::load_generation::{make_bundle, tps_to_millis};
use timeboost_utils::select_peer_hosts;
use timeboost_utils::types::logging::init_logging;
use tokio::signal::{
    ctrl_c,
    unix::{SignalKind, signal},
};
use tokio::time::interval;
use tracing::{error, info};
use tx::{send_bundle_to_node, setup_clients_and_urls};

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
        info!("waiting for peer: {}", address);
        wait_for_live_peer(address.clone()).await?;
        address.set_port(800 + address.port());
        all_hosts_as_addresses.push(address);
    }

    let mut interval = interval(Duration::from_millis(tps_to_millis(cli.tps)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let jh = tokio::spawn({
        let keyset = keyset.clone();
        let pubkey = keyset.dec_keyset().pubkey()?;
        let client_and_urls = setup_clients_and_urls(&all_hosts_as_addresses)
            .expect("Failed to setup clients and URLs");
        async move {
            loop {
                // create a bundle, and send this bundle to each host
                let result = make_bundle(&pubkey);
                interval.tick().await;

                match result {
                    Ok(bundle) => {
                        let send_txns_futs = client_and_urls.iter().map(
                            |(client, regular_url, priority_url)| async {
                                send_bundle_to_node(
                                    &bundle,
                                    client,
                                    regular_url.as_str(),
                                    priority_url.as_str(),
                                )
                                .await
                            },
                        );
                        let results = futures::future::join_all(send_txns_futs).await;
                        for result in results {
                            if let Err(err) = result {
                                error!(%err, "failed to send");
                            }
                        }
                    }
                    Err(err) => {
                        error!(%err, "failed to generate bundle");
                    }
                }
            }
        }
    });

    let mut signal = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c() => {
            info!("Received Ctrl+C, shutting down yapper...");
        },
        _ = signal.recv() => {
            info!("Received SIGTERM, shutting down yapper...");
        },
    }
    jh.abort();
    Ok(())
}
