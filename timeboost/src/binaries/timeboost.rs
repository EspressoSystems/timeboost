use std::path::PathBuf;

use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result, bail};
use cliquenet::AddressableCommittee;
use multisig::CommitteeId;
use multisig::{Committee, Keypair, x25519};
use timeboost::{Timeboost, TimeboostConfig};
use timeboost_builder::robusta;
use timeboost_contract::{CommitteeManager, CommitteeMemberSol};
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_types::{KeyStore, ThresholdKeyCell};
use tokio::select;
use tokio::signal;
use tokio::task::spawn;
use tracing::info;

use clap::Parser;
use timeboost::config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, NodeConfig};
use timeboost::types::UNKNOWN_COMMITTEE_ID;
use timeboost_utils::types::logging;
use tracing::warn;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    config: PathBuf,

    /// CommitteeId for the committee in which this member belongs to
    #[clap(long, short)]
    committee_id: CommitteeId,

    /// Ignore any existing stamp file and start from genesis.
    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// Submitter should connect only with https?
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,

    /// Path to committee config toml.
    #[cfg(feature = "until")]
    #[clap(long)]
    committee: PathBuf,

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
    let provider = ProviderBuilder::new().connect_http(node_config.chain.parent.rpc_url.clone());
    let chain_id = provider.get_chain_id().await?;

    assert_eq!(
        chain_id, node_config.chain.parent.id,
        "parent chain rpc has mismatched chain_id"
    );

    let contract = KeyManager::new(node_config.chain.parent.key_manager_contract, &provider);

    let members: Vec<CommitteeMemberSol> = contract
        .getCommitteeById(cli.committee_id.into())
        .call()
        .await?
        .members;

    info!(label = %sign_keypair.public_key(), committee_id = %cli.committee_id, "committee info synced");

    let peer_hosts_and_keys = members
        .iter()
        .map(|peer| {
            let sig_key = multisig::PublicKey::try_from(peer.sigKey.as_ref())
                .expect("Failed to parse sigKey");
            let dh_key =
                x25519::PublicKey::try_from(peer.dhKey.as_ref()).expect("Failed to parse dhKey");
            let dkg_enc_key = DkgEncKey::from_bytes(peer.dkgKey.as_ref())
                .expect("Blackbox from_bytes should work");
            let sailfish_address = cliquenet::Address::try_from(peer.networkAddress.as_ref())
                .expect("Failed to parse networkAddress");
            (sig_key, dh_key, dkg_enc_key, sailfish_address)
        })
        .collect::<Vec<_>>();

    let mut sailfish_peer_hosts_and_keys = Vec::new();
    let mut decrypt_peer_hosts_and_keys = Vec::new();
    let mut certifier_peer_hosts_and_keys = Vec::new();
    let mut dkg_enc_keys = Vec::new();

    for (signing_key, dh_key, dkg_enc_key, sailfish_addr) in peer_hosts_and_keys.iter().cloned() {
        sailfish_peer_hosts_and_keys.push((signing_key, dh_key, sailfish_addr.clone()));
        decrypt_peer_hosts_and_keys.push((
            signing_key,
            dh_key,
            sailfish_addr.clone().with_offset(DECRYPTER_PORT_OFFSET),
        ));
        certifier_peer_hosts_and_keys.push((
            signing_key,
            dh_key,
            sailfish_addr.clone().with_offset(CERTIFIER_PORT_OFFSET),
        ));
        dkg_enc_keys.push(dkg_enc_key.clone());
    }

    let sailfish_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            sailfish_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, sailfish_peer_hosts_and_keys.iter().cloned())
    };

    let decrypt_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            decrypt_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, decrypt_peer_hosts_and_keys.iter().cloned())
    };

    let certifier_committee = {
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            certifier_peer_hosts_and_keys
                .iter()
                .enumerate()
                .map(|(i, (k, ..))| (i as u8, *k)),
        );
        AddressableCommittee::new(c, certifier_peer_hosts_and_keys.iter().cloned())
    };

    let key_store = KeyStore::new(
        sailfish_committee.committee().clone(),
        dkg_enc_keys
            .into_iter()
            .enumerate()
            .map(|(i, k)| (i as u8, k)),
    );

    let is_recover = !cli.ignore_stamp && node_config.stamp.is_file();

    tokio::fs::File::create(&node_config.stamp)
        .await
        .with_context(|| format!("Failed to create stamp file: {:?}", node_config.stamp))?
        .sync_all()
        .await
        .with_context(|| "Failed to sync stamp file to disk")?;

    let pubkey = sign_keypair.public_key();

    let config = TimeboostConfig::builder()
        .sailfish_committee(sailfish_committee)
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
        .chain_config(node_config.chain.clone())
        .build();

    let timeboost = Timeboost::new(config.clone()).await?;

    let event_monitor_handle = config.event_monitoring().enabled().then(|| {
        let provider =
            ProviderBuilder::new().connect_http(node_config.chain.parent.rpc_url.clone());
        let event_monitor = timeboost::event_monitor::EventMonitor::new(
            provider,
            node_config.chain.parent.key_manager_contract,
            config.event_monitoring().clone(),
        );

        spawn(async move {
            if let Err(e) = event_monitor.start_monitoring().await {
                error!("Event monitoring failed: {}", e);
            }
        })
    });

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

        let committee = CommitteeConfig::read(&cli.committee)
            .await
            .with_context(|| format!("failed to read committee config {:?}", cli.committee))?;

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
    if let Some(mut event_handle) = event_monitor_handle {
        select! {
            _ = timeboost.go() => bail!("timeboost shutdown unexpectedly"),
            _ = &mut grpc => bail!("grpc api shutdown unexpectedly"),
            _ = &mut api => bail!("api service shutdown unexpectedly"),
            _ = &mut event_handle => {
                bail!("event monitor shutdown unexpectedly")
            },
            _ = signal::ctrl_c() => {
                warn!("received ctrl-c; shutting down");
                api.abort();
                grpc.abort();
                event_handle.abort();
            }
        }
    } else {
        select! {
            _ = timeboost.go() => bail!("timeboost shutdown unexpectedly"),
            _ = &mut grpc => bail!("grpc api shutdown unexpectedly"),
            _ = &mut api => bail!("api service shutdown unexpectedly"),
            _ = signal::ctrl_c() => {
                warn!("received ctrl-c; shutting down");
                api.abort();
                grpc.abort();
            }
        }
    }

    Ok(())
}
