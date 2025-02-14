use anyhow::{bail, ensure, Context, Result};
use multisig::{Keypair, PublicKey, SecretKey};
use serde_json::from_str;
use std::collections::HashMap;
use std::fs;
use std::time::Duration;
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use timeboost::{Keyset, PrivDecInfo, Timeboost, TimeboostInitializer};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::types::NodeId;
use timeboost_crypto::sg_encryption::KeyShare;
use timeboost_crypto::G;
use tokio::net::lookup_host;
use tokio::time::sleep;

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

    /// NON PRODUCTION: A deterministic key generator is used for local/cloud testing. The format
    /// will just be a list of addresses since keys are deterministic. So if we have 5 nodes like in
    /// docker it'll just be
    /// [
    ///     "172.20.0.2",
    ///     "172.20.0.3",
    ///     "172.20.0.4",
    ///     "172.20.0.5",
    ///     "172.20.0.6"
    /// ]
    #[clap(long)]
    keyfile: PathBuf,

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
    #[clap(long, name = "KEY_FILE", env = "ESPRESSO_SEQUENCER_KEY_FILE")]
    pub key_file: Option<PathBuf>,

    /// Private signature key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_SIGNATURE_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    pub private_signature_key: Option<String>,

    /// Private decryption key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_DECRYPTION_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    pub private_decryption_key: Option<String>,

    /// The ip address of the nitro node for gas estimations.
    #[clap(long)]
    nitro_node_url: Option<reqwest::Url>,
}

fn read_keyset(path: PathBuf) -> Result<Keyset> {
    ensure!(path.exists(), "File not found: {:?}", path);
    let data = fs::read_to_string(&path).context("Failed to read file")?;
    let keyset: Keyset = from_str(&data).context("Failed to parse JSON")?;
    Ok(keyset)
}

async fn resolve_with_retries(host: &str) -> SocketAddr {
    loop {
        if let Ok(mut addresses) = lookup_host(host).await {
            if let Some(addr) = addresses.next() {
                break addr;
            }
        }
        sleep(Duration::from_secs(2)).await;
        tracing::error!(%host, "looking up peer host");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    // Parse the CLI arguments for the node ID and port
    let cli = Cli::parse();
    let num = cli.nodes.unwrap_or(5);

    let id = NodeId::from(cli.id as u64);
    let (sig_priv_key, dec_priv_key) = private_keys(&cli)?;
    let keypair = Keypair::from_private_key(sig_priv_key);

    let keyset = read_keyset(cli.keyfile).expect("keyfile to exist and be valid");
    let dec_key = PrivDecInfo {
        pubkey: keyset.dec_keyset.pubkey,
        combkey: keyset.dec_keyset.combkey,
        privkey: dec_priv_key,
    };

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = keyset
        .keyset
        .iter()
        .take(num)
        .map(|ph| format!("http://{}", ph.url).parse().unwrap())
        .collect();

    let mut peer_hosts_and_keys = Vec::new();

    for peer_host in keyset.keyset.into_iter().take(num) {
        let resolved_addr = match peer_host.url.parse::<SocketAddr>() {
            Ok(addr) => addr, // It's already an IP address with a port
            Err(_) => resolve_with_retries(&peer_host.url).await,
        };
        let pub_key: PublicKey =
            PublicKey::try_from(&peer_host.pubkey).expect("derive public key from bytes");
        peer_hosts_and_keys.push((pub_key, resolved_addr));
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
            tracing::warn!("Adding delay before starting node: id: {}", id);
            tokio::time::sleep(std::time::Duration::from_secs(LATE_START_DELAY_SECS)).await;
        }
        task_handle
    };

    let committee_size = peer_hosts_and_keys.len();
    let init = TimeboostInitializer {
        id,
        rpc_port: cli.rpc_port,
        metrics_port: cli.metrics_port,
        peers: peer_hosts_and_keys,
        keypair,
        dec_key,
        bind_address,
        nitro_url: cli.nitro_node_url,
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
        }
    }
    #[cfg(not(feature = "until"))]
    tokio::select! {
        _ = timeboost.go(committee_size, cli.tps) => {
            anyhow::bail!("timeboost shutdown unexpectedly");
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
        }
    }
    Ok(())
}

fn private_keys(cli: &Cli) -> anyhow::Result<(SecretKey, KeyShare<G>)> {
    if let Some(path) = &cli.key_file {
        let vars = dotenvy::from_path_iter(path)?.collect::<Result<HashMap<_, _>, _>>()?;
        let sig_key_string = vars
            .get("TIMEBOOST_PRIVATE_SIGNATURE_KEY")
            .context("key file missing ESPRESSO_SEQUENCER_PRIVATE_STAKING_KEY")?;
        let sig_key =
            multisig::SecretKey::try_from(bs58::decode(sig_key_string).into_vec()?.as_slice())?;
        let dec_key_string = vars
            .get("ESPRESSO_SEQUENCER_PRIVATE_STATE_KEY")
            .context("key file missing ESPRESSO_SEQUENCER_PRIVATE_STATE_KEY")?;
        let dec_key: KeyShare<G> = bincode::deserialize(&bs58::decode(dec_key_string).into_vec()?)?;

        Ok((sig_key, dec_key))
    } else if let (Some(sig_key), Some(dec_key)) = (
        cli.private_signature_key.clone(),
        cli.private_decryption_key.clone(),
    ) {
        let sig_key = multisig::SecretKey::try_from(bs58::decode(sig_key).into_vec()?.as_slice())?;
        let dec_key = bincode::deserialize(&bs58::decode(dec_key).into_vec()?)?;

        Ok((sig_key, dec_key))
    } else {
        bail!("neither key file nor full set of private keys was provided")
    }
}
