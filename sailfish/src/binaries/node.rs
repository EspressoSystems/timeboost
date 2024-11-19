use anyhow::Result;
use clap::Parser;
use hotshot::traits::implementations::derive_libp2p_multiaddr;
use hotshot_types::PeerConfig;
use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use sailfish::sailfish;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashSet, fs};
use timeboost_core::logging;
use timeboost_core::types::metrics::ConsensusMetrics;
use timeboost_core::types::{Keypair, NodeId, PublicKey};
use tokio::sync::mpsc::channel;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    config_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    to_connect_addrs: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    id: NodeId,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    let cfg: Config = toml::from_str(&fs::read_to_string(cli.config_path)?)?;
    let keypair = Keypair::zero(cfg.id);
    let bind_address = derive_libp2p_multiaddr(&format!("0.0.0.0:{}", cfg.port)).unwrap();

    // Sailfish nodes running individually do not need to communicate with the
    // application layer, so we make dummy streams.
    let (sf_app_tx, _) = channel(1);
    let (_, tb_app_rx) = channel(1);
    let (shutdown_tx, shutdown_rx) = async_channel::bounded(1);
    let metrics = Arc::new(ConsensusMetrics::default());

    sailfish::run_sailfish(
        cfg.id,
        cfg.to_connect_addrs,
        cfg.staked_nodes,
        keypair,
        bind_address,
        sf_app_tx,
        tb_app_rx,
        metrics,
        shutdown_tx,
        shutdown_rx,
    )
    .await
}
