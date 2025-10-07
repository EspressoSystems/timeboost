use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use multisig::CommitteeId;
use multisig::{Keypair, x25519};
use timeboost::committee::CommitteeInfo;
use timeboost::{Timeboost, TimeboostConfig};
use timeboost_builder::robusta;
use timeboost_types::ThresholdKeyCell;
use tokio::select;
use tokio::signal;
use tokio::task::spawn;
use tracing::info;

use clap::Parser;
use timeboost::config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, NodeConfig};
use timeboost_utils::types::logging;
use tracing::warn;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long, short)]
    config: PathBuf,

    /// Ignore any existing stamp file and start from genesis.
    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// Submitter should connect only with https?
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,

    #[cfg(feature = "until")]
    #[clap(long)]
    start_delay: Option<u64>,

    #[cfg(feature = "until")]
    #[clap(long)]
    required_decrypt_rounds: Option<u64>,

    #[clap(long)]
    times_until: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let node_config = NodeConfig::read(&cli.config)
        .await
        .with_context(|| format!("could not read node config {:?}", cli.config))?;

    let sign_keypair = Keypair::from(node_config.keys.signing.secret.clone());
    let dh_keypair = x25519::Keypair::from(node_config.keys.dh.secret.clone());

    // syncing with contract to get peers keys and network addresses
    let comm_info = CommitteeInfo::fetch(
        node_config.chain.parent.rpc_url.clone(),
        node_config.chain.parent.key_manager_contract,
        node_config.committee,
    )
    .await?;

    info!(
        label        = %sign_keypair.public_key(),
        committee_id = %node_config.committee,
        "committee info synced"
    );

    let sailfish_committee = comm_info.sailfish_committee();
    let decrypt_committee = comm_info.decrypt_committee();
    let certifier_committee = comm_info.certifier_committee();
    let key_store = comm_info.dkg_key_store();

    let is_recover = !cli.ignore_stamp && node_config.stamp.is_file();

    tokio::fs::File::create(&node_config.stamp)
        .await
        .with_context(|| format!("Failed to create stamp file: {:?}", node_config.stamp))?
        .sync_all()
        .await
        .with_context(|| "Failed to sync stamp file to disk")?;

    let pubkey = sign_keypair.public_key();

    let prev_comm = if node_config.committee > CommitteeId::default() {
        let c = &node_config.chain.parent;
        let p = node_config.committee - 1;
        let prev_comm = CommitteeInfo::fetch(c.rpc_url.clone(), c.key_manager_contract, p).await?;
        Some(prev_comm)
    } else {
        None
    };

    let config = TimeboostConfig::builder()
        .sailfish_committee(sailfish_committee)
        .registered_blk(*comm_info.registered_block())
        .maybe_prev_committee(prev_comm)
        .decrypt_committee(decrypt_committee)
        .certifier_committee(certifier_committee)
        .sign_keypair(sign_keypair)
        .dh_keypair(dh_keypair)
        .dkg_key(node_config.keys.dkg.secret)
        .key_store(key_store)
        .sailfish_addr(node_config.net.public.address.clone())
        .decrypt_addr(
            node_config
                .net
                .public
                .address
                .clone()
                .with_offset(DECRYPTER_PORT_OFFSET),
        )
        .certifier_addr(
            node_config
                .net
                .public
                .address
                .clone()
                .with_offset(CERTIFIER_PORT_OFFSET),
        )
        .maybe_nitro_addr(node_config.net.internal.nitro.clone())
        .recover(is_recover)
        .threshold_dec_key(ThresholdKeyCell::new())
        .robusta((
            robusta::Config::builder()
                .base_url(node_config.espresso.base_url)
                .wss_base_url(node_config.espresso.websockets_base_url)
                .label(pubkey.to_string())
                .https_only(cli.https_only)
                .build(),
            Vec::new(),
        ))
        .max_transaction_size(node_config.espresso.max_transaction_size)
        .chain_config(node_config.chain.clone());

    #[cfg(feature = "times")]
    let config = config.maybe_times_until(cli.times_until).build();
    #[cfg(not(feature = "times"))]
    let config = config.build();

    let timeboost = Timeboost::new(config).await?;

    let mut grpc = {
        let addr = node_config.net.internal.address.to_string();
        spawn(timeboost.internal_grpc_api().serve(addr))
    };

    let mut api = spawn(
        timeboost
            .api()
            .serve(node_config.net.public.http_api.to_string()),
    );

    #[cfg(feature = "until")]
    {
        use anyhow::bail;
        use std::time::Duration;
        use timeboost_config::CommitteeConfig;
        use timeboost_utils::until::Until;
        use tokio::time::sleep;
        use url::Url;

        let committee_conf = cli.config.with_file_name("committee.toml");
        let committee = CommitteeConfig::read(&committee_conf.to_str().unwrap())
            .await
            .with_context(|| format!("failed to read committee config {:?}", committee_conf))?;

        let handle = {
            let Some(member) = committee
                .members
                .iter()
                .find(|m| m.signing_key == node_config.keys.signing.public)
            else {
                bail!("failed to find node in committee")
            };

            let host: Url = format!("http://{}", member.http_api)
                .parse()
                .context("invalid http api address")?;

            if let Some(s) = cli.start_delay {
                warn!("delaying start by {s}s");
                sleep(Duration::from_secs(s)).await;
            }

            let mut until = Until::new(cli.until, Duration::from_secs(cli.watchdog_timeout), host);
            until.require_decrypted(cli.required_decrypt_rounds);

            spawn(until.run())
        };

        select! {
            res = handle => {
                tracing::info!("watchdog completed");
                return match res {
                    Ok(Ok(_))  => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(e)     => Err(e.into())
                };
            },
            _ = timeboost.go()   => bail!("timeboost shutdown unexpectedly"),
            _ = &mut grpc        => bail!("grpc api shutdown unexpectedly"),
            _ = &mut api         => bail!("api service shutdown unexpectedly"),
            _ = signal::ctrl_c() => {
                warn!("received ctrl-c; shutting down");
                api.abort();
                grpc.abort();
            }
        }
    }

    #[cfg(not(feature = "until"))]
    select! {
        _ = timeboost.go()   => bail!("timeboost shutdown unexpectedly"),
        _ = &mut grpc        => bail!("grpc api shutdown unexpectedly"),
        _ = &mut api         => bail!("api service shutdown unexpectedly"),
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            api.abort();
            grpc.abort();
        }
    }

    Ok(())
}
