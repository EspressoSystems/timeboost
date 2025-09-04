use std::path::PathBuf;

use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result, bail};
use cliquenet::AddressableCommittee;
use multisig::CommitteeId;
use multisig::{Committee, Keypair, x25519};
use timeboost::{Timeboost, TimeboostConfig};
use timeboost_builder::robusta;
use timeboost_contract::{CommitteeMemberSol, KeyManager};
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_types::{KeyStore, ThresholdKeyCell};
use tokio::select;
use tokio::signal;
use tokio::task::spawn;
use url::Url;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_utils::until::run_until;

use clap::Parser;
use timeboost::config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, NodeConfig};
use timeboost::types::UNKNOWN_COMMITTEE_ID;
use timeboost_utils::types::logging;
use timeboost_utils::wait_for_live_peer;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

#[derive(Parser, Debug)]
struct Cli {
    /// CommitteeId for the committee in which this member belongs to
    #[clap(long, short)]
    committee_id: CommitteeId,

    /// API service port.
    #[clap(long)]
    http_port: u16,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    config: PathBuf,

    /// Backwards compatibility. This allows for a single region to run (i.e. local)
    #[clap(long, default_value_t = false)]
    multi_region: bool,

    /// Path to a file that this process creates or reads as execution proof.
    #[clap(long)]
    stamp: PathBuf,

    /// Ignore any existing stamp file and start from genesis.
    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,

    /// Base URL of Espresso's REST API.
    #[clap(
        long,
        default_value = "https://query.decaf.testnet.espresso.network/v1/"
    )]
    espresso_base_url: Url,

    /// Base URL of Espresso's Websocket API.
    #[clap(long, default_value = "wss://query.decaf.testnet.espresso.network/v1/")]
    espresso_websocket_url: Url,

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

    /// The id of a node that will start late.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 0)]
    late_start_node_id: u16,

    /// The flag if we want to late start a node
    #[cfg(feature = "until")]
    #[clap(long, short, action = clap::ArgAction::SetTrue)]
    late_start: bool,
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
    assert_eq!(
        provider.get_chain_id().await?,
        node_config.chain.parent.id,
        "Parent chain RPC has mismatched chain_id"
    );
    let contract = KeyManager::new(node_config.chain.parent.key_manager_contract, &provider);
    let members: Vec<CommitteeMemberSol> = contract
        .getCommitteeById(cli.committee_id.into())
        .call()
        .await?
        .members;
    tracing::info!(
        label = %sign_keypair.public_key(),
        committee_id = %cli.committee_id,
        "committee info synced"
    );

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

    #[cfg(feature = "until")]
    let node_idx = peer_hosts_and_keys
        .iter()
        .position(|p| p.0 == node_config.keys.signing.public)
        .expect("node's sigKey should be a member of Committee");

    #[cfg(feature = "until")]
    let peer_urls: Vec<Url> = peer_hosts_and_keys
        .iter()
        .map(|peer| format!("http://{}", peer.3).parse().unwrap())
        .collect();

    let mut sailfish_peer_hosts_and_keys = Vec::new();
    let mut decrypt_peer_hosts_and_keys = Vec::new();
    let mut certifier_peer_hosts_and_keys = Vec::new();
    let mut dkg_enc_keys = Vec::new();

    for (signing_key, dh_key, dkg_enc_key, sailfish_addr) in peer_hosts_and_keys {
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

    let is_recover = !cli.ignore_stamp && cli.stamp.is_file();

    tokio::fs::File::create(&cli.stamp)
        .await
        .with_context(|| format!("Failed to create stamp file: {:?}", cli.stamp))?
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
                .base_url(cli.espresso_base_url)
                .wss_base_url(cli.espresso_websocket_url)
                .label(pubkey.to_string())
                .https_only(cli.https_only)
                .build(),
            Vec::new(),
        ))
        .chain_config(node_config.chain.clone())
        .build();

    let timeboost = Timeboost::new(config).await?;

    let mut grpc = {
        let addr = node_config.net.internal.address.to_string();
        spawn(timeboost.internal_grpc_api().serve(addr))
    };

    let mut api = spawn(timeboost.api().serve(format!("0.0.0.0:{}", cli.http_port)));

    for peer in sailfish_peer_hosts_and_keys {
        let p = peer.2.port();
        wait_for_live_peer(&peer.2.with_port(p + 800)).await? // TODO: remove port magic
    }

    #[cfg(feature = "until")]
    let handle = {
        ensure!(peer_urls.len() >= node_idx, "Not enough peers");
        let mut host = peer_urls[node_idx].clone();

        host.set_port(Some(host.port().unwrap() + 800)).unwrap(); // TODO: remove port magic

        let task_handle = spawn(run_until(cli.until, cli.watchdog_timeout, host));
        if cli.late_start && node_idx as u16 == cli.late_start_node_id {
            warn!("Adding delay before starting node: id: {}", node_idx);
            tokio::time::sleep(std::time::Duration::from_secs(LATE_START_DELAY_SECS)).await;
        }
        task_handle
    };

    #[cfg(feature = "until")]
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
