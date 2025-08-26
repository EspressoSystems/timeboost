use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use cliquenet::AddressableCommittee;
use multisig::{Committee, Keypair, x25519};
use timeboost::{Timeboost, TimeboostConfig};
use timeboost_builder::robusta;
use timeboost_types::{DecryptionKeyCell, KeyStore};
use tokio::select;
use tokio::signal;
use tokio::task::spawn;
use url::Url;

#[cfg(feature = "until")]
use anyhow::ensure;
#[cfg(feature = "until")]
use timeboost_utils::until::run_until;

use clap::Parser;
use timeboost::types::UNKNOWN_COMMITTEE_ID;
use timeboost_utils::keyset::{KeysetConfig, wait_for_live_peer};
use timeboost_utils::types::logging;
use tracing::warn;

#[cfg(feature = "until")]
const LATE_START_DELAY_SECS: u64 = 15;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// API service port.
    #[clap(long)]
    http_port: u16,

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

    /// Hotshot namespace for a chain
    #[clap(long)]
    namespace: u64,

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

    let keyset = KeysetConfig::read_keyset(&cli.keyset_file)
        .with_context(|| format!("could not read keyset file {:?}", cli.keyset_file))?;

    // Ensure the config exists for this keyset
    let my_keyset = keyset
        .keyset
        .get(cli.id as usize)
        .expect("keyset for this node to exist");

    let private = my_keyset
        .private
        .clone()
        .ok_or_else(|| anyhow!("missing private keys for node"))?;

    let sign_keypair = Keypair::from(private.signing_key);
    let dh_keypair = x25519::Keypair::from(private.dh_key);

    #[cfg(feature = "until")]
    let peer_urls: Vec<Url> = keyset
        .keyset
        .iter()
        .map(|ph| format!("http://{}", ph.sailfish_address).parse().unwrap())
        .collect();

    let peer_host_iter = timeboost_utils::select_peer_hosts(&keyset.keyset, cli.multi_region);

    let mut sailfish_peer_hosts_and_keys = Vec::new();
    let mut decrypt_peer_hosts_and_keys = Vec::new();
    let mut certifier_peer_hosts_and_keys = Vec::new();
    let mut dkg_enc_keys = Vec::new();

    for peer_host in peer_host_iter {
        sailfish_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.sailfish_address.clone(),
        ));
        decrypt_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.decrypt_address.clone(),
        ));
        certifier_peer_hosts_and_keys.push((
            peer_host.signing_key,
            peer_host.dh_key,
            peer_host.certifier_address.clone(),
        ));
        dkg_enc_keys.push(peer_host.enc_key.clone());
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
        .dkg_key(private.dec_key.clone())
        .key_store(key_store)
        .sailfish_addr(my_keyset.sailfish_address.clone())
        .decrypt_addr(my_keyset.decrypt_address.clone())
        .certifier_addr(my_keyset.certifier_address.clone())
        .maybe_nitro_addr(my_keyset.nitro_addr.clone())
        .recover(is_recover)
        .threshold_dec_key(DecryptionKeyCell::new())
        .robusta((
            robusta::Config::builder()
                .base_url(cli.espresso_base_url)
                .wss_base_url(cli.espresso_websocket_url)
                .label(pubkey.to_string())
                .https_only(cli.https_only)
                .build(),
            Vec::new(),
        ))
        .namespace(cli.namespace)
        .chain_config(my_keyset.chain_config.clone())
        .build();

    let timeboost = Timeboost::new(config).await?;

    let mut grpc = {
        let addr = my_keyset.internal_address.to_string();
        spawn(timeboost.internal_grpc_api().serve(addr))
    };

    let mut api = spawn(timeboost.api().serve(format!("0.0.0.0:{}", cli.http_port)));

    for peer in sailfish_peer_hosts_and_keys {
        let p = peer.2.port();
        wait_for_live_peer(&peer.2.with_port(p + 800)).await? // TODO: remove port magic
    }

    #[cfg(feature = "until")]
    let handle = {
        ensure!(peer_urls.len() >= usize::from(cli.id), "Not enough peers");
        let mut host = peer_urls[usize::from(cli.id)].clone();

        host.set_port(Some(host.port().unwrap() + 800)).unwrap(); // TODO: remove port magic

        let task_handle = spawn(run_until(cli.until, cli.watchdog_timeout, host));
        if cli.late_start && cli.id == cli.late_start_node_id {
            warn!("Adding delay before starting node: id: {}", cli.id);
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
