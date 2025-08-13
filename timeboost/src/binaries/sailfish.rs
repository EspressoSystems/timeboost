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
use timeboost_utils::{keyset::KeysetConfig, select_peer_hosts};

use timeboost_utils::types::{logging, prometheus::PrometheusMetrics};
use tokio::{select, signal};
use tracing::{error, info};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

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

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let keyset =
        KeysetConfig::read_keyset(&cli.keyset_file).context("Failed to read keyset file")?;

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

    let peer_hosts_and_keys = select_peer_hosts(&keyset.keyset, cli.multi_region)
        .map(|peer| (peer.signing_key, peer.dh_key, peer.sailfish_address.clone()))
        .collect::<Vec<_>>();

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

    for a in coordinator.init() {
        if let Err(err) = coordinator.execute(a).await {
            error!(%err, "error executing coordinator action");
        }
    }

    loop {
        select! { biased;
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
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
