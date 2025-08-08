use std::{iter::repeat_with, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use cliquenet::{Network, NetworkMetrics, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Committee, Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::{Action, HasTime, Timestamp, UNKNOWN_COMMITTEE_ID},
};
use serde::{Deserialize, Serialize};
use timeboost::{metrics_api, rpc_api};
use timeboost_types::DecryptionKeyCell;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};

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

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

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
struct Block(Timestamp, #[serde(with = "serde_bytes")] [u8; 512]);

impl Block {
    fn random() -> Self {
        Self(Timestamp::now(), rand::random())
    }
}

impl Committable for Block {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Block")
            .field("time", self.0.commit())
            .var_size_bytes(&self.1)
            .finalize()
    }
}

impl HasTime for Block {
    fn time(&self) -> Timestamp {
        self.0
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
                                info!(round_number = %payload.round().num(), "payload delivered");
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
                                info!(round_number = %payload.round().num(), "payload delivered");
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
    let enc_key = DecryptionKeyCell::new();

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

    let rpc = spawn(rpc_api(app_tx, enc_key, cli.rpc_port));

    let my_keyset = keyset
        .keyset
        .get(cli.id as usize)
        .context("Keyset for this node does not exist")?;

    let private = my_keyset
        .private
        .clone()
        .ok_or_else(|| anyhow!("missing private keys for node"))?;

    let signing_keypair = Keypair::from(private.signing_key);
    let dh_keypair = x25519::Keypair::from(private.dh_key);

    #[cfg(feature = "until")]
    let peer_urls: Vec<reqwest::Url> = {
        let mut urls = Vec::new();
        for ph in keyset.keyset.iter() {
            let url = format!("http://{}", ph.sailfish_address)
                .parse()
                .context(format!(
                    "Failed to parse URL: http://{}",
                    ph.sailfish_address
                ))?;
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

    let peer_host_iter = timeboost_utils::select_peer_hosts(&keyset.keyset, cli.multi_region);

    let mut peer_hosts_and_keys = Vec::new();

    for peer_host in peer_host_iter {
        wait_for_live_peer(peer_host.sailfish_address.clone()).await?;
        peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.sailfish_address.clone(),
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
        my_keyset.sailfish_address.clone(),
        signing_keypair.public_key(),
        dh_keypair.clone(),
        peer_hosts_and_keys.clone(),
        net_metrics,
    )
    .await?;

    let metrics = spawn(metrics_api(prom.clone(), cli.metrics_port));

    let committee = Committee::new(
        UNKNOWN_COMMITTEE_ID,
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

    let cfg =
        RbcConfig::new(signing_keypair.clone(), committee.id(), committee.clone()).recover(recover);

    let rbc = Rbc::new(
        committee.size().get() * 5,
        Overlay::new(network),
        cfg.with_metrics(rbc_metrics),
    );

    let consensus = Consensus::new(signing_keypair, committee, repeat_with(Block::random))
        .with_metrics(sf_metrics);
    let mut coordinator = Coordinator::new(rbc, consensus, false);

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
