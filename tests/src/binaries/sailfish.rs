use std::{iter::repeat_with, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use cliquenet::{Network, NetworkMetrics, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use metrics::prometheus::PrometheusMetrics;
use multisig::{Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::{Action, HasTime, Timestamp},
};
use serde::{Deserialize, Serialize};
use timeboost::config::{CommitteeContract, NodeConfig};
use timeboost_utils::logging;
use tokio::{select, signal};
use tracing::{error, info};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to node configuration.
    #[clap(long, short)]
    node: PathBuf,

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

    let config = NodeConfig::read(&cli.node)
        .await
        .context("Failed to read node config")?;

    let signing_keypair = Keypair::from(config.keys.signing.secret.clone());
    let sign_pubkey = signing_keypair.public_key();
    let dh_keypair = x25519::Keypair::from(config.keys.dh.secret.clone());

    let mut contract = CommitteeContract::from(&config);
    let committee = contract.active().await?;

    if committee.member(&sign_pubkey).is_none() {
        bail!("{sign_pubkey} not a member of the active committee")
    }

    let prom = Arc::new(PrometheusMetrics::default());
    let sf_metrics = ConsensusMetrics::new(prom.as_ref());
    let net_metrics = NetworkMetrics::new(
        "sailfish",
        prom.as_ref(),
        committee.members.iter().map(|m| m.signing_key),
    );
    let rbc_metrics = RbcMetrics::new(prom.as_ref());
    let network = Network::create(
        "sailfish",
        config.net.bind.clone(),
        signing_keypair.public_key(),
        dh_keypair.clone(),
        committee.sailfish().entries(),
        net_metrics,
    )
    .await?;

    // If the stamp file exists we need to recover from a previous run.
    let recover = if cli.ignore_stamp {
        false
    } else {
        tokio::fs::try_exists(&config.stamp).await?
    };

    let committee = committee.committee();

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
    tokio::fs::File::create(config.stamp)
        .await?
        .sync_all()
        .await?;

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
                                if !writer.is_sailfish_saved() && r >= cli.times_until {
                                    writer.save_sailfish_series().await?
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

    Ok(())
}
