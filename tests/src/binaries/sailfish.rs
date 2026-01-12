use std::{iter::repeat_with, path::PathBuf};

use anyhow::{Context, Result, bail};
use cliquenet::{NetConf, Network, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::Consensus,
    rbc::{Rbc, RbcConfig},
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
    config: PathBuf,

    /// How many rounds to run.
    #[clap(long, default_value_t = 1000)]
    until: u64,
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

    let conf = NodeConfig::read(&cli.config)
        .await
        .context("failed to read node config")?;

    let signing_keypair = Keypair::from(conf.keys.signing.secret.clone());
    let sign_pubkey = signing_keypair.public_key();
    let dh_keypair = x25519::Keypair::from(conf.keys.dh.secret.clone());

    let mut contract = CommitteeContract::from(&conf.chain);
    let committee = contract.active().await?;

    if committee.member(&sign_pubkey).is_none() {
        bail!("{sign_pubkey} not a member of the active committee")
    }

    let network = {
        let cfg = NetConf::builder()
            .name("sailfish")
            .label(signing_keypair.public_key())
            .keypair(dh_keypair.clone())
            .bind(conf.net.bind.clone())
            .parties(committee.sailfish().entries())
            .build();
        Network::create(cfg).await?
    };

    let committee = committee.committee();

    let cfg = RbcConfig::new(signing_keypair.clone(), committee.id(), committee.clone())
        .with_handshake(false);

    let rbc = Rbc::new(committee.size().get() * 5, Overlay::new(network), cfg);

    let consensus = Consensus::new(signing_keypair, committee, repeat_with(Block::random));
    let mut coordinator = Coordinator::new(rbc, consensus, false);

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
