use std::{iter::repeat_with, path::PathBuf, sync::Arc};

use ::metrics::prometheus::PrometheusMetrics;
use anyhow::{Context, Result};
use cliquenet::{Network, NetworkMetrics, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::{Action, HasTime, Timestamp},
};
use serde::{Deserialize, Serialize};
use timeboost::{committee::CommitteeInfo, config::NodeConfig};
use timeboost_utils::types::logging;
use tokio::{select, signal};
use tracing::{error, info};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to node configuration.
    #[clap(long, short)]
    config: PathBuf,

    /// Path to a file that this process creates or reads as execution proof.
    #[clap(long)]
    stamp: PathBuf,

    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// How many rounds to run.
    #[clap(long, default_value_t = 1000)]
    until: u64,

    #[cfg(feature = "times")]
    #[clap(long)]
    times_until: u64,
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

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let config = NodeConfig::read(&cli.config)
        .await
        .context("Failed to read node config")?;

    let signing_keypair = Keypair::from(config.keys.signing.secret.clone());
    let dh_keypair = x25519::Keypair::from(config.keys.dh.secret.clone());

    // syncing with contract to get peers keys and network addresses
    let comm_info = CommitteeInfo::fetch(
        config.chain.parent.rpc_url,
        config.chain.parent.key_manager_contract,
        config.committee,
    )
    .await?;

    info!(
        label        = %config.keys.signing.public,
        committee_id = %config.committee,
        "committee info synced"
    );

    let prom = Arc::new(PrometheusMetrics::default());
    let sf_metrics = ConsensusMetrics::new(prom.as_ref());
    let net_metrics = NetworkMetrics::new(
        "sailfish",
        prom.as_ref(),
        comm_info.signing_keys().iter().cloned(),
    );
    let rbc_metrics = RbcMetrics::new(prom.as_ref());
    let network = Network::create(
        "sailfish",
        config.net.public.address.clone(),
        signing_keypair.public_key(),
        dh_keypair.clone(),
        comm_info.address_info(),
        net_metrics,
    )
    .await?;

    let committee = comm_info.committee();

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

    #[cfg(feature = "times")]
    let mut writer = timeboost::times::TimesWriter::new(config.keys.signing.public);

    // Create proof of execution.
    tokio::fs::File::create(cli.stamp).await?.sync_all().await?;

    #[cfg(feature = "times")]
    let start = std::time::Instant::now();

    for a in coordinator.init() {
        if let Err(err) = coordinator.execute(a).await {
            error!(%err, "error executing coordinator action");
        }
    }

    'main: loop {
        select! {
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                let r = *payload.round().num();
                                #[cfg(feature = "times")]
                                {
                                    times::record_once("sf-round-end", r);
                                    if !writer.is_sailfish_saved() && r >= cli.times_until {
                                        writer.save_sailfish_series().await?
                                    }
                                }
                                if r >= cli.until {
                                    break 'main
                                }
                                info!(round = %payload.round().num(), "payload delivered");
                            } else if let Err(err) = coordinator.execute(a).await {
                                error!(%err, "error executing action");
                            }
                        }
                    },
                    Err(err) => {
                        error!(%err, "error getting next actions");
                    },
                }
            }
            _ = signal::ctrl_c() => {
                info!("received ctrl-c; shutting down");
                break;
            }
        }
    }

    #[cfg(feature = "times")]
    {
        let elapsed = start.elapsed();
        info!(
            target: "times",
            elapsed      = ?elapsed,
            rounds       = %cli.until,
            ms_per_round = %(elapsed.as_secs_f64() / cli.until as f64 * 1000.0)
        );
    }

    Ok(())
}
