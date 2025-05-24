use std::{
    iter::repeat_with,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use cliquenet::{Network, NetworkMetrics, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Committee, Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::Action,
};
use serde::{Deserialize, Serialize};
use timeboost::{metrics_api, rpc_api};
use timeboost_utils::keyset::{KeysetConfig, PrivateKeys, wait_for_live_peer};

use timeboost_utils::types::{logging, prometheus::PrometheusMetrics};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::spawn;
use tracing::info;

use clap::Parser;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_utils::until::run_until;
#[cfg(feature = "until")]
use tokio::task::JoinHandle;

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

    /// The port of the node to build.
    #[clap(long)]
    port: u16,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// NON PRODUCTION: Specify the number of nodes to run.
    #[clap(long)]
    nodes: usize,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

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

    /// Private DH key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(long, env = "TIMEBOOST_DH_PRIVATE_KEY", conflicts_with = "KEY_FILE")]
    private_dh_key: Option<String>,

    /// Private decryption key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_DECRYPTION_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    private_decryption_key: Option<String>,

    /// Backwards compatibility. This allows for a single region to run (i.e. local)
    #[clap(long, default_value_t = false)]
    multi_region: bool,

    /// Path to a file that this process creates or reads as execution proof.
    #[clap(long)]
    stamp: PathBuf,

    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,
}

/// Payload data type is a block of 512 random bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Block(#[serde(with = "serde_bytes")] [u8; 512]);

impl Block {
    fn random() -> Self {
        Self(rand::random())
    }
}

impl Committable for Block {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Block")
            .var_size_bytes(&self.0)
            .finalize()
    }
}

async fn run(
    mut coordinator: Coordinator<Block, Rbc<Block>>,
    #[cfg(feature = "until")] mut until_task: JoinHandle<()>,
) -> Result<()> {
    loop {
        #[cfg(feature = "until")]
        tokio::select! { biased;
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                info!(round_number = *payload.round(), "payload delivered");
                            } else if let Err(e) = coordinator.execute(a).await {
                                tracing::error!("Error receiving message: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error receiving message: {}", e);
                    },
                }
            }
            _ = &mut until_task => {
                tracing::info!("watchdog completed");
                return Ok(());
            }
            _ = signal::ctrl_c() => {
                info!("received ctrl-c; shutting down");
                break;
            }
        }

        #[cfg(not(feature = "until"))]
        tokio::select! { biased;
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                info!(round_number = *payload.round(), "payload delivered");
                            } else if let Err(e) = coordinator.execute(a).await {
                                tracing::error!("Error receiving message: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error receiving message: {}", e);
                    },
                }
            }
            _ = signal::ctrl_c() => {
                info!("received ctrl-c; shutting down");
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let keyset =
        KeysetConfig::read_keyset(&cli.keyset_file).context("Failed to read keyset file")?;

    let (app_tx, mut app_rx) = mpsc::channel(1024);

    // Spin app_rx in a background thread and just drop the messages using a tokio select.
    // Exiting when we get a ctrl-c.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = app_rx.recv() => {}
                _ = signal::ctrl_c() => {
                    break;
                }
            }
        }
    });

    let rpc = spawn(rpc_api(app_tx, cli.rpc_port));

    let my_keyset = keyset
        .keyset()
        .get(cli.id as usize)
        .context("Keyset for this node does not exist")?;

    let (sig_key, dh_key, _) = if let Some(keys) = &my_keyset.private {
        keys.parse()?
    } else if let Some(path) = cli.key_file {
        PrivateKeys::read(path)?.parse()?
    } else {
        let sig = cli
            .private_signature_key
            .ok_or_else(|| anyhow!("missing private_signature_key"))?
            .as_str()
            .try_into()
            .context("invalid private_signature_key")?;
        let dh = cli
            .private_dh_key
            .ok_or_else(|| anyhow!("missing private_dh_key"))?
            .as_str()
            .try_into()
            .context("invalid private_dh_key")?;
        let dec = cli
            .private_decryption_key
            .ok_or_else(|| anyhow!("missing private_decryption_key"))?;
        PrivateKeys { sig, dh, dec }.parse()?
    };

    let signing_keypair = Keypair::from(sig_key);
    let dh_keypair = x25519::Keypair::from(dh_key);

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = {
        let mut urls = Vec::new();
        for ph in keyset.keyset().iter().take(cli.nodes) {
            let url = format!("http://{}", ph.sailfish_url)
                .parse()
                .context(format!("Failed to parse URL: http://{}", ph.sailfish_url))?;
            urls.push(url);
        }
        urls
    };

    #[cfg(feature = "until")]
    let until_task = {
        ensure!(peer_urls.len() >= usize::from(cli.id), "Not enough peers");
        let mut host = peer_urls[usize::from(cli.id)].clone();

        // Set the port (9000 + i in the local setup)
        host.port().context("Invalid port in URL")?;
        host.set_port(Some(host.port().unwrap() + 1000))
            .map_err(|_| anyhow::anyhow!("Failed to set port in URL"))?;

        // Map the Result<(), anyhow::Error> to () to match the expected JoinHandle<()> type
        let task_handle = tokio::spawn(async move {
            if let Err(e) = run_until(cli.until, cli.watchdog_timeout, host).await {
                tracing::error!("Until task failed: {}", e);
            }
        });
        task_handle
    };

    let peer_host_iter =
        timeboost_utils::select_peer_hosts(keyset.keyset(), cli.nodes, cli.multi_region);

    let mut peer_hosts_and_keys = Vec::new();

    for peer_host in peer_host_iter {
        wait_for_live_peer(peer_host.sailfish_url.clone()).await?;
        peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.sailfish_url.clone(),
        ));
    }

    let prom = Arc::new(PrometheusMetrics::default());
    let sf_metrics = ConsensusMetrics::new(prom.as_ref());
    let net_metrics = NetworkMetrics::new(
        "sailfish",
        prom.as_ref(),
        peer_hosts_and_keys.iter().map(|(k, ..)| *k),
    );
    let rbc_metrics = RbcMetrics::new(prom.as_ref());
    let network = Network::create(
        "sailfish",
        bind_address,
        signing_keypair.clone(),
        dh_keypair.clone(),
        peer_hosts_and_keys.clone(),
        net_metrics,
    )
    .await?;

    let metrics = spawn(metrics_api(prom.clone(), cli.metrics_port));

    let committee = Committee::new(
        peer_hosts_and_keys
            .iter()
            .map(|b| b.0)
            .enumerate()
            .map(|(i, key)| (i as u8, key)),
    );

    // If the stamp file exists we need to recover from a previous run.
    let recover = if cli.ignore_stamp {
        false
    } else {
        tokio::fs::try_exists(&cli.stamp).await?
    };

    let cfg = RbcConfig::new(signing_keypair.clone(), committee.clone()).recover(recover);
    let rbc = Rbc::new(Overlay::new(network), cfg.with_metrics(rbc_metrics));

    let consensus = Consensus::new(signing_keypair, committee, repeat_with(Block::random))
        .with_metrics(sf_metrics);
    let mut coordinator = Coordinator::new(rbc, consensus);

    // Create proof of execution.
    tokio::fs::File::create(cli.stamp).await?.sync_all().await?;

    // Kickstart the network.
    for a in coordinator.init() {
        if let Err(e) = coordinator.execute(a).await {
            tracing::error!("Error executing coordinator action: {}", e);
        }
    }

    let result = run(
        coordinator,
        #[cfg(feature = "until")]
        until_task,
    )
    .await;

    rpc.abort();
    metrics.abort();

    result
}
