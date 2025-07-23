use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use cliquenet::AddressableCommittee;
use multisig::{Committee, Keypair, x25519};
use timeboost::{Timeboost, TimeboostConfig, rpc_api};

use timeboost_builder::robusta;
use tokio::signal;
use tokio::sync::mpsc::channel;
use tokio::task::spawn;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_utils::until::run_until;

use clap::Parser;
use timeboost::types::UNKNOWN_COMMITTEE_ID;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::types::logging;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// The port of the RPC API.
    #[clap(long)]
    rpc_port: u16,

    /// The port of the metrics server.
    #[clap(long)]
    metrics_port: u16,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

    /// The id of a node that will start late.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 0)]
    late_start_node_id: u16,

    /// The flag if we want to late start a node
    #[cfg(feature = "until")]
    #[clap(long, short, action = clap::ArgAction::SetTrue)]
    late_start: bool,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// The ip address of the nitro node for gas estimations.
    #[clap(long)]
    nitro_node_url: Option<reqwest::Url>,

    /// Backwards compatibility. This allows for a single region to run (i.e. local)
    #[clap(long, default_value_t = false)]
    multi_region: bool,

    /// Path to a file that this process creates or reads as execution proof.
    #[clap(long)]
    stamp: PathBuf,

    /// Ignore any existing stamp file and start from genesis.
    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// Base URL of Espresso's REST API.
    #[clap(
        long,
        default_value = "https://query.decaf.testnet.espresso.network/v1/"
    )]
    espresso_base_url: String,

    /// Base URL of Espresso's Websocket API.
    #[clap(long, default_value = "wss://query.decaf.testnet.espresso.network/v1/")]
    espresso_websocket_url: String,

    #[clap(long)]
    namespace: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    // Read public key material
    let keyset = KeysetConfig::read_keyset(&cli.keyset_file)
        .with_context(|| format!("could not read keyset file {:?}", cli.keyset_file))?;

    // Ensure the config exists for this keyset
    let my_keyset = keyset
        .keyset
        .get(cli.id as usize)
        .expect("keyset for this node to exist");

    let private = my_keyset
        .private
        .clone()
        .ok_or_else(|| anyhow!("missing private keys for node"))?;

    let sign_keypair = Keypair::from(private.signing_key);
    let dh_keypair = x25519::Keypair::from(private.dh_key);
    let dec_sk = keyset.decryption_key(private.dec_share);

    let (tb_app_tx, tb_app_rx) = channel(100);

    // The RPC api needs to be started first before everything else so that way we can verify the
    // health check.
    let api_handle = spawn(rpc_api(tb_app_tx.clone(), cli.rpc_port));

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = keyset
        .keyset
        .iter()
        .map(|ph| format!("http://{}", ph.sailfish_address).parse().unwrap())
        .collect();

    let peer_host_iter = timeboost_utils::select_peer_hosts(&keyset.keyset, cli.multi_region);

    let mut sailfish_peer_hosts_and_keys = Vec::new();
    let mut decrypt_peer_hosts_and_keys = Vec::new();
    let mut certifier_peer_hosts_and_keys = Vec::new();

    for peer_host in peer_host_iter {
        wait_for_live_peer(peer_host.sailfish_address.clone()).await?;

        sailfish_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.sailfish_address.clone(),
        ));
        decrypt_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.decrypt_address.clone(),
        ));
        certifier_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.certifier_address.clone(),
        ));
    }

    let sailfish_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            sailfish_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, sailfish_peer_hosts_and_keys.iter().cloned())
    };

    let decrypt_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            decrypt_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, decrypt_peer_hosts_and_keys.iter().cloned())
    };

    let certifier_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            certifier_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, certifier_peer_hosts_and_keys.iter().cloned())
    };

    #[cfg(feature = "until")]
    let handle = {
        ensure!(peer_urls.len() >= usize::from(cli.id), "Not enough peers");
        let mut host = peer_urls[usize::from(cli.id)].clone();

        // HACK: The port is always 9000 + i in the local setup
        host.set_port(Some(host.port().unwrap() + 1000)).unwrap();

        let task_handle = tokio::spawn(run_until(cli.until, cli.watchdog_timeout, host));
        if cli.late_start && cli.id == cli.late_start_node_id {
            tracing::warn!("Adding delay before starting node: id: {}", cli.id);
            tokio::time::sleep(std::time::Duration::from_secs(LATE_START_DELAY_SECS)).await;
        }
        task_handle
    };

    let is_recover = !cli.ignore_stamp && cli.stamp.is_file();

    tokio::fs::File::create(&cli.stamp)
        .await
        .with_context(|| format!("Failed to create stamp file: {:?}", cli.stamp))?
        .sync_all()
        .await
        .with_context(|| "Failed to sync stamp file to disk")?;

    let pubkey = sign_keypair.public_key();
    let config = TimeboostConfig::builder()
        .metrics_port(cli.metrics_port)
        .sailfish_committee(sailfish_committee)
        .decrypt_committee(decrypt_committee)
        .certifier_committee(certifier_committee)
        .sign_keypair(sign_keypair)
        .dh_keypair(dh_keypair)
        .decryption_key(dec_sk)
        .sailfish_addr(my_keyset.sailfish_address.clone())
        .decrypt_addr(my_keyset.decrypt_address.clone())
        .certifier_addr(my_keyset.certifier_address.clone())
        .internal_api(my_keyset.internal_address.clone())
        .maybe_nitro_addr(my_keyset.nitro_addr.clone())
        .recover(is_recover)
        .robusta(
            robusta::Config::builder()
                .base_url(&cli.espresso_base_url)?
                .wss_base_url(&cli.espresso_websocket_url)?
                .label(pubkey.to_string())
                .build(),
        )
        .namespace(cli.namespace)
        .build();

    let timeboost = Timeboost::new(config, tb_app_rx).await?;

    #[cfg(feature = "until")]
    tokio::select! {
        res = handle => {
            tracing::info!("watchdog completed");
            return match res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => anyhow::bail!("Error: {}", e),
            };
        },
        _ = timeboost.go() => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api_handle.abort();
        }
    }
    #[cfg(not(feature = "until"))]
    tokio::select! {
        _ = timeboost.go() => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api_handle.abort();
        }
    }
    Ok(())
}
