use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use multisig::{Keypair, x25519};
use timeboost::{Timeboost, TimeboostConfig};
use timeboost_builder::robusta;
use timeboost_config::{ChainConfig, CommitteeContract};
use timeboost_config::{GRPC_API_PORT_OFFSET, HTTP_API_PORT_OFFSET};
use timeboost_types::{ThresholdKeyCell, Timestamp};
use tokio::select;
use tokio::signal;
use tokio::task::spawn;
use tracing::{error, info};

use clap::Parser;
use timeboost::config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, NodeConfig};
use timeboost_utils::logging;
use tracing::warn;

#[derive(Parser, Debug)]
struct Cli {
    /// Timeboost node config file.
    #[clap(long, short)]
    node: PathBuf,

    /// Ignore any existing stamp file and start from genesis.
    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// Submitter should connect only with https?
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,

    #[cfg(feature = "times")]
    #[clap(long)]
    times_until: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let node = NodeConfig::read(&cli.node)
        .await
        .with_context(|| format!("could not read node config {:?}", cli.node))?;

    let sign_keypair = Keypair::from(node.keys.signing.secret.clone());
    let sign_pubkey = sign_keypair.public_key();
    let dh_keypair = x25519::Keypair::from(node.keys.dh.secret.clone());

    let mut contract = CommitteeContract::from(&node.chain);
    let mut committee = contract.active().await?;
    let mut prev_committee = None;

    if committee.member(&sign_pubkey).is_none() {
        let Some(next) = contract.next(committee.id).await? else {
            bail!("{sign_pubkey} not a member of the active committee and no next committee exists")
        };
        if next.member(&sign_pubkey).is_none() {
            bail!("{sign_pubkey} not a member of the active nor the next committee")
        }
        info!(
            node      = %sign_pubkey,
            committee = %next.id,
            previous  = %committee.id,
            "awaiting previous committee"
        );
        prev_committee = Some(committee);
        committee = next;
    }

    let is_recover = !cli.ignore_stamp && node.stamp.is_file();

    tokio::fs::File::create(&node.stamp)
        .await
        .with_context(|| format!("Failed to create stamp file: {:?}", node.stamp))?
        .sync_all()
        .await
        .with_context(|| "Failed to sync stamp file to disk")?;

    let pubkey = sign_keypair.public_key();

    let config = TimeboostConfig::builder()
        .sailfish_committee(committee.sailfish())
        .maybe_prev_committee(prev_committee)
        .decrypt_committee(committee.decrypt())
        .certifier_committee(committee.certify())
        .sign_keypair(sign_keypair)
        .dh_keypair(dh_keypair)
        .dkg_key(node.keys.dkg.secret)
        .key_store(committee.dkg_key_store())
        .sailfish_addr(node.net.bind.clone())
        .decrypt_addr(node.net.bind.clone().with_offset(DECRYPTER_PORT_OFFSET))
        .certifier_addr(node.net.bind.clone().with_offset(CERTIFIER_PORT_OFFSET))
        .nitro_addr(node.net.nitro.clone())
        .recover(is_recover)
        .threshold_dec_key(ThresholdKeyCell::new())
        .robusta((
            robusta::Config::builder()
                .base_url(node.espresso.base_url)
                .maybe_builder_base_url(node.espresso.builder_base_url)
                .wss_base_url(node.espresso.websockets_base_url)
                .label(pubkey.to_string())
                .https_only(cli.https_only)
                .build(),
            Vec::new(),
        ))
        .namespace(node.espresso.namespace)
        .max_transaction_size(node.espresso.max_transaction_size)
        .chain_config(node.chain.clone());

    #[cfg(feature = "times")]
    let config = config.times_until(cli.times_until).build();
    #[cfg(not(feature = "times"))]
    let config = config.build();

    let committees = contract.subscribe(committee.id).await?;
    let timeboost = Timeboost::new(config, committees).await?;

    let mut grpc = {
        let addr = node
            .net
            .bind
            .clone()
            .with_offset(GRPC_API_PORT_OFFSET)
            .to_string();
        spawn(timeboost.internal_grpc_api().serve(addr))
    };

    let mut api = spawn(
        timeboost.api().serve(
            node.net
                .bind
                .clone()
                .with_offset(HTTP_API_PORT_OFFSET)
                .to_string(),
        ),
    );

    select! {
        r = timeboost.go() => {
            if let Err(err) = r {
                error!(%err, "fatal timeboost error")
            }
            bail!("timeboost shutdown unexpectedly")
        }
        r = &mut grpc => {
            if let Err(err) = r {
                error!(%err, "fatal grpc error")
            }
            bail!("grpc api shutdown unexpectedly")
        }
        r = &mut api => {
            if let Err(err) = r {
                error!(%err, "fatal api error")
            }
            bail!("api service shutdown unexpectedly")
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api.abort();
            grpc.abort();
        }
    }

    Ok(())
}
