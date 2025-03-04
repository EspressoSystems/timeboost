use anyhow::{Context, Result};
use cliquenet::{Address, Network, NetworkMetrics};
use multisig::{Committee, Keypair, PublicKey};
use sailfish::{
    consensus::{Consensus, ConsensusMetrics},
    rbc::{Rbc, RbcConfig, RbcMetrics},
    types::Action,
    Coordinator,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use timeboost::{
    keyset::{private_keys, wait_for_live_peer, Keyset},
    start_metrics_api, start_rpc_api, TransactionQueue,
};
use timeboost_utils::types::{logging, prometheus::PrometheusMetrics};
use tokio::{signal, sync::mpsc};
use tracing::info;

use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    /// The ID of the node to build.
    #[clap(long)]
    id: u16,

    /// The port of the RPC API.
    #[clap(long)]
    rpc_port: u16,

    /// The port of the metrics server.
    #[clap(long)]
    metrics_port: u16,

    /// The port of the node to build.
    #[clap(long)]
    port: u16,

    /// Path to file containing the keyset description.
    ///
    /// The file contains backend urls and public key material.
    #[clap(long)]
    keyset_file: PathBuf,

    /// NON PRODUCTION: Specify the number of nodes to run.
    #[clap(long)]
    nodes: Option<usize>,

    /// Path to file containing private keys.
    ///
    /// The file should follow the .env format, with two keys:
    /// * TIMEBOOST_SIGNATURE_PRIVATE_KEY
    /// * TIMEBOOST_DECRYPTION_PRIVATE_KEY
    ///
    /// Appropriate key files can be generated with the `keygen` utility program.
    #[clap(long, name = "KEY_FILE", env = "TIMEBOOST_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Private signature key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_SIGNATURE_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    private_signature_key: Option<String>,

    /// Private decryption key.
    ///
    /// This can be used as an alternative to KEY_FILE.
    #[clap(
        long,
        env = "TIMEBOOST_DECRYPTION_PRIVATE_KEY",
        conflicts_with = "KEY_FILE"
    )]
    private_decryption_key: Option<String>,

    /// Backwards compatibility. This allows for a single region to run (i.e. local)
    #[clap(long, default_value_t = false)]
    multi_region: bool,

    /// The number of transactions to generate per second.
    #[clap(long, default_value_t = 100)]
    tps: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();
    let num = cli.nodes.unwrap_or(4);

    let keyset = Keyset::read_keyset(cli.keyset_file).expect("keyfile to exist and be valid");

    let (app_tx, mut app_rx) = mpsc::channel(1024);

    // Spin app_rx in a background thread and just drop the messages using a tokio select. Exiting when we
    // get a ctrl-c.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = app_rx.recv() => {}
                _ = signal::ctrl_c() => {
                    break;
                }
            }
        }
    });

    info!("starting rpc api");
    let rpc = start_rpc_api(app_tx, cli.rpc_port);

    let my_keyset = keyset
        .keyset()
        .get(cli.id as usize)
        .expect("keyset for this node to exist");

    // Now, fetch the signature private key and decryption private key, preference toward the JSON config.
    // Note that the clone of the two fields explicitly avoids cloning the entire `PublicNodeInfo`.
    let (sig_key, _) = match (my_keyset.sig_pk.clone(), my_keyset.dec_pk.clone()) {
        // We found both in the JSON, we're good to go.
        (Some(sig_pk), Some(dec_pk)) => {
            let sig_key = multisig::SecretKey::try_from(sig_pk.as_str())
                .context("converting key string to secret key")?;
            let dec_key = bincode::deserialize(
                &bs58::decode(dec_pk)
                    .into_vec()
                    .context("unable to decode bs58")?,
            )?;

            (sig_key, dec_key)
        }
        // Hard crash on misconfigurations in the JSON (i.e. one key unset).
        (Some(..), None) | (None, Some(..)) => {
            panic!("malformed JSON configuration, both `sig_pk` and `dec_pk` must be set");
        }
        // Last try: Can we pick these eys from the environment or other provided key(s)?
        _ => private_keys(
            cli.key_file,
            cli.private_signature_key,
            cli.private_decryption_key,
        )?,
    };

    let keypair = Keypair::from(sig_key);

    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cli.port));

    let mut peer_hosts_and_keys = Vec::new();

    // Rust is *really* picky about mixing iterators, so we just erase the type.
    let peer_host_iter: Box<dyn Iterator<Item = &_>> = if cli.multi_region {
        // The number of nodes to take from the group. The layout of the nodes is such that (in the cloud) each region
        // continues sequentially from the prior region. So if us-east-2 has nodes 0, 1, 2, 3 and us-west-2 has nodes
        // 4, 5, 6, 7, then we need to offset this otherwise we'd attribute us-east-2 nodes to us-west-2.
        let take_from_group = num / 4;

        Box::new(
            keyset
                .keyset()
                .chunks(4)
                .flat_map(move |v| v.iter().take(take_from_group)),
        )
    } else {
        // Fallback behavior for multi regions, we just take the first n nodes if we're running on a single region or all
        // on the same host.
        Box::new(keyset.keyset().iter().take(num))
    };

    // So we take chunks of 4 per region (this is ALWAYS 4), then, take `take_from_group` node keys from each chunk.
    for peer_host in peer_host_iter {
        let mut spl = peer_host.url.splitn(3, ":");
        let p0 = spl.next().expect("valid url");
        let p1: u16 = spl
            .next()
            .expect("valid port")
            .parse()
            .expect("integer port");
        let peer_address = Address::from((p0, p1));
        wait_for_live_peer(peer_address.clone()).await?;

        let pubkey =
            PublicKey::try_from(peer_host.pubkey.as_str()).expect("derive public signature key");
        peer_hosts_and_keys.push((pubkey, peer_address));
    }

    let prom = Arc::new(PrometheusMetrics::default());
    let sf_metrics = ConsensusMetrics::new(prom.as_ref());
    let net_metrics =
        NetworkMetrics::new(prom.as_ref(), peer_hosts_and_keys.iter().map(|(k, _)| *k));
    let rbc_metrics = RbcMetrics::new(prom.as_ref());
    let network = Network::create(
        bind_address,
        keypair.clone(),
        peer_hosts_and_keys.clone(),
        net_metrics,
    )
    .await?;

    info!("starting metrics api");
    let metrics = start_metrics_api(prom.clone(), cli.metrics_port);
    let committee = Committee::new(
        peer_hosts_and_keys
            .iter()
            .map(|b| b.0)
            .enumerate()
            .map(|(i, key)| (i as u8, key)),
    );

    let cfg = RbcConfig::new(keypair.clone(), committee.clone());
    let rbc = Rbc::new(network, cfg.with_metrics(rbc_metrics));
    let producer = TransactionQueue::new();

    let consensus = Consensus::new(keypair, committee, producer.clone()).with_metrics(sf_metrics);
    let mut coordinator = Coordinator::new(rbc, consensus);

    // Kickstart the network.
    for a in coordinator.init() {
        let _ = coordinator.execute(a).await;
    }
    info!("network kicked off");

    loop {
        tokio::select! { biased;
            result = coordinator.next() => {
                match result {
                    Ok(actions) => {
                        for a in actions {
                            if let Action::Deliver(payload) = a {
                                info!(
                                    round_number = *payload.round(),
                                    size = payload.data().size_bytes(),
                                    transactions = payload.data().len(),
                                    "block delivered"
                                );
                            } else if let Err(e) = coordinator.execute(a).await {
                                tracing::error!("Error receiving message: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Error receiving message: {}", e);
                    },
                }
            }
            _ = signal::ctrl_c() => {
                info!("received ctrl-c; shutting down");
                metrics.abort();
                rpc.abort();
                break;
            }
        }
    }
    Ok(())
}
