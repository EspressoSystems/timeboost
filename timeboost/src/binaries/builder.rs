use anyhow::{Context, Result};
use cliquenet::Address;
use multisig::{Keypair, PublicKey};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use timeboost::{
    keyset::{private_keys, wait_for_live_peer, Keyset},
    start_rpc_api, Timeboost, TimeboostInitializer,
};
use timeboost_core::traits::has_initializer::HasInitializer;

use tokio::sync::mpsc::channel;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_core::until::run_until;

use clap::Parser;
use timeboost_utils::types::logging;
use tokio::signal;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

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

    /// NON PRODUCTION: An internal load generator will generate at a rate of X per second.
    /// Set this to 0 for no load generation.
    #[clap(long, short, default_value_t = 100)]
    tps: u32,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// NON PRODUCTION: Specify the number of nodes to run.
    #[clap(long)]
    nodes: Option<usize>,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();
    let num = cli.nodes.unwrap_or(5);

    // Read public key material
    let keyset = Keyset::read_keyset(cli.keyset_file).expect("keyfile to exist and be valid");

    // Ensure the config exists for this keyset
    let my_keyset = keyset
        .keyset()
        .get(cli.id as usize)
        .expect("keyset for this node to exist");

    // Now, fetch the signature private key and decryption private key, preference toward the JSON config.
    // Note that the clone of the two fields explicitly avoids cloning the entire `PublicNodeInfo`.
    let (sig_key, dec_key) = match (my_keyset.sig_pk.clone(), my_keyset.dec_pk.clone()) {
        // We found both in the JSON, we're good to go.
        (Some(sig_pk), Some(dec_pk)) => {
            let sig_key = multisig::SecretKey::try_from(sig_pk.as_str())
                .context("converting key string to secret key")?;
            let dec_key = bincode::deserialize(
                &bs58::decode(dec_pk)
                    .into_vec()
                    .context("unable to decode bs58")?,
            )?;

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
    let deckey = keyset
        .build_decryption_material(dec_key)
        .expect("parse keyset");

    let (tb_app_tx, tb_app_rx) = channel(100);

    // The RPC api needs to be started first before everything else so that way we can verify the
    // health check.
    let api_handle = start_rpc_api(tb_app_tx.clone(), cli.rpc_port);

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = keyset
        .keyset()
        .iter()
        .take(num)
        .map(|ph| format!("http://{}", ph.url).parse().unwrap())
        .collect();

    let mut peer_hosts_and_keys = Vec::new();

    for peer_host in keyset.keyset().iter().take(num) {
        let mut spl = peer_host.url.splitn(3, ":");
        let p0 = spl.next().expect("valid url");
        let p1: u16 = spl
            .next()
            .expect("valid port")
            .parse()
            .expect("integer port");
        let peer_address = Address::from((p0, p1));
        wait_for_live_peer(peer_address.clone()).await?;

        let pubkey =
            PublicKey::try_from(peer_host.pubkey.as_str()).expect("derive public signature key");
        peer_hosts_and_keys.push((pubkey, peer_address));
    }

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));
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

    let committee_size = peer_hosts_and_keys.len();
    let init = TimeboostInitializer {
        rpc_port: cli.rpc_port,
        metrics_port: cli.metrics_port,
        peers: peer_hosts_and_keys,
        keypair,
        deckey,
        bind_address,
        nitro_url: cli.nitro_node_url,
        app_tx: tb_app_tx,
        app_rx: tb_app_rx,
    };

    let timeboost = Timeboost::initialize(init).await?;

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
        _ = timeboost.go(committee_size, cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api_handle.abort();
        }
    }
    #[cfg(not(feature = "until"))]
    tokio::select! {
        _ = timeboost.go(committee_size, cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api_handle.abort();
        }
    }
    Ok(())
}
