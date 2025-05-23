use anyhow::{Context, Result};
use cliquenet::Address;
use multisig::{Keypair, PublicKey};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use timeboost::{Timeboost, TimeboostConfig, rpc_api};

use tokio::signal;
use tokio::sync::mpsc::channel;
use tokio::task::spawn;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_utils::until::run_until;

use clap::Parser;
use timeboost_utils::keyset::{KeysetConfig, private_keys, wait_for_live_peer};
use timeboost_utils::types::logging;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// The listen address of the sailfish node.
    #[clap(long)]
    sailfish_addr: String,

    /// The listen address of the decrypt node.
    #[clap(long)]
    decrypt_addr: String,

    /// The listen address of the producer node.
    #[clap(long)]
    producer_addr: String,

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

    /// NON PRODUCTION: Specify the number of nodes to run.
    #[clap(long)]
    nodes: usize,

    /// Path to file containing private keys.
    ///
    /// The file should follow the .env format, with two keys:
    /// * TIMEBOOST_SIGNATURE_PRIVATE_KEY
    /// * TIMEBOOST_DECRYPTION_PRIVATE_KEY
    ///
    /// Appropriate key files can be generated with the `keygen` utility program.
    #[clap(long, name = "KEY_FILE", env = "TIMEBOOST_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Private signature key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_SIGNATURE_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    private_signature_key: Option<String>,

    /// Private decryption key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_DECRYPTION_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    private_decryption_key: Option<String>,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();

    // Read public key material
    let keyset =
        KeysetConfig::read_keyset(&cli.keyset_file).context("keyfile to exist and be valid")?;

    // Ensure the config exists for this keyset
    let my_keyset = keyset
        .keyset()
        .get(cli.id as usize)
        .expect("keyset for this node to exist");

    // Now, fetch the signature private key and decryption private key, preference toward the JSON config.
    // Note that the clone of the two fields explicitly avoids cloning the entire `PublicNodeInfo`.
    let (sig_key, dec_sk) = match (my_keyset.sig_pk.clone(), my_keyset.dec_pk.clone()) {
        // We found both in the JSON, we're good to go.
        (Some(sig_pk), Some(dec_pk)) => {
            let sig_key = multisig::SecretKey::try_from(sig_pk.as_str())
                .context("converting key string to secret key")?;
            let dec_key = bincode::serde::decode_from_slice(
                &bs58::decode(dec_pk)
                    .into_vec()
                    .context("unable to decode bs58")?,
                bincode::config::standard(),
            )?
            .0;

            (sig_key, dec_key)
        }
        // Hard crash on misconfigurations in the JSON (i.e. one key unset).
        (Some(..), None) | (None, Some(..)) => {
            panic!("malformed JSON configuration, both `sig_pk` and `dec_pk` must be set");
        }
        // Last try: Can we pick these eys from the environment or other provided key(s)?
        _ => private_keys(
            cli.key_file,
            cli.private_signature_key,
            cli.private_decryption_key,
        )?,
    };

    let keypair = Keypair::from(sig_key);

    let dec_sk = keyset
        .build_decryption_material(dec_sk)
        .expect("parse keyset");

    let (tb_app_tx, tb_app_rx) = channel(100);

    // The RPC api needs to be started first before everything else so that way we can verify the
    // health check.
    let api_handle = spawn(rpc_api(tb_app_tx.clone(), cli.rpc_port));

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = keyset
        .keyset()
        .iter()
        .take(cli.nodes)
        .map(|ph| format!("http://{}", ph.sailfish_url).parse().unwrap())
        .collect();

    let peer_host_iter =
        timeboost_utils::select_peer_hosts(keyset.keyset(), cli.nodes, cli.multi_region);

    let mut sailfish_peer_hosts_and_keys = Vec::new();
    let mut decrypt_peer_hosts_and_keys = Vec::new();
    let mut producer_peer_hosts_and_keys = Vec::new();

    for peer_host in peer_host_iter {
        let sailfish_address = Address::from_str(&peer_host.sailfish_url)?;
        let decrypt_address = Address::from_str(&peer_host.decrypt_url)?;
        let producer_address = Address::from_str(&peer_host.producer_url)?;

        wait_for_live_peer(sailfish_address.clone()).await?;

        let pubkey = PublicKey::try_from(&*peer_host.pubkey)
            .context("failed to derive public signature key")?;

        sailfish_peer_hosts_and_keys.push((pubkey, sailfish_address));
        decrypt_peer_hosts_and_keys.push((pubkey, decrypt_address));
        producer_peer_hosts_and_keys.push((pubkey, producer_address));
    }

    let sailfish_address =
        SocketAddr::from_str(&cli.sailfish_addr).context("failed to parse sailfish address")?;

    let decrypt_address =
        SocketAddr::from_str(&cli.decrypt_addr).context("failed to parse decrypt address")?;

    let producer_address =
        SocketAddr::from_str(&cli.producer_addr).context("failed to parse producer address")?;

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

    let init = TimeboostConfig {
        rpc_port: cli.rpc_port,
        metrics_port: cli.metrics_port,
        sailfish_peers: sailfish_peer_hosts_and_keys,
        decrypt_peers: decrypt_peer_hosts_and_keys,
        producer_peers: producer_peer_hosts_and_keys,
        keypair,
        dec_sk,
        sailfish_address,
        decrypt_address,
        producer_address,
        nitro_url: cli.nitro_node_url,
        sender: tb_app_tx,
        receiver: tb_app_rx,
        stamp: cli.stamp,
        ignore_stamp: cli.ignore_stamp,
    };

    let timeboost = Timeboost::new(init).await?;

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
