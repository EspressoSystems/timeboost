use std::{iter::repeat_with, path::PathBuf, sync::Arc, time::Duration};

use alloy::providers::Provider;
use anyhow::{Context, Result, anyhow};
use cliquenet::{Network, NetworkMetrics, Overlay};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Committee, CommitteeId, Keypair, x25519};
use sailfish::{
    Coordinator,
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::{Action, HasTime, Timestamp, UNKNOWN_COMMITTEE_ID},
};
use serde::{Deserialize, Serialize};
use timeboost_contract::{CommitteeMemberSol, KeyManager};
use timeboost_utils::keyset::NodeConfig;
use timeboost_utils::types::{logging, prometheus::PrometheusMetrics};
use tokio::{select, signal, time::sleep};
use tracing::{error, info};

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// CommitteeId for the committee in which this member belongs to
    #[clap(long, short)]
    committee_id: CommitteeId,
    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    config_file: PathBuf,

    /// How many rounds to run.
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// Max. number of seconds to run.
    #[clap(long, default_value_t = 30)]
    timeout: u64,

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

    let config = NodeConfig::read(&cli.config_file).context("Failed to read node config")?;

    let private = config
        .private
        .as_ref()
        .ok_or_else(|| anyhow!("missing private keys for node"))?;

    let signing_keypair = Keypair::from(private.signing_key().clone());
    let dh_keypair = x25519::Keypair::from(private.dh_key().clone());

    // syncing with contract to get peers keys and network addresses
    let provider = config.chain_config.provider();
    assert_eq!(
        provider.get_chain_id().await?,
        config.chain_config.parent_chain_id(),
        "Parent chain RPC has mismatched chain_id"
    );
    let contract = KeyManager::new(config.chain_config.key_manager_contr_addr(), &provider);
    let members: Vec<CommitteeMemberSol> = contract
        .getCommitteeById(cli.committee_id.into())
        .call()
        .await?
        .members;
    let peer_hosts_and_keys = members
        .iter()
        .map(|peer| {
            let sig_key = multisig::PublicKey::try_from(peer.sigKey.as_ref())
                .expect("Failed to parse sigKey");
            let dh_key =
                x25519::PublicKey::try_from(peer.dhKey.as_ref()).expect("Failed to parse dhKey");
            let sailfish_address = cliquenet::Address::try_from(peer.networkAddress.as_ref())
                .expect("Failed to parse networkAddress");
            (sig_key, dh_key, sailfish_address)
        })
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
        config.net.sailfish_address.clone(),
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

    let mut timeout = Box::pin(sleep(Duration::from_secs(cli.timeout)));

    'main: loop {
        select! {
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                if *payload.round().num() >= cli.until {
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
            _ = &mut timeout => {
                error!("timeout");
                break;
            }
            _ = signal::ctrl_c() => {
                info!("received ctrl-c; shutting down");
                break;
            }
        }
    }

    Ok(())
}
