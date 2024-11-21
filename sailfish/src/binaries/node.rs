use ::sailfish::sailfish::sailfish_coordinator;
use anyhow::Result;
use clap::Parser;
use hotshot::traits::implementations::derive_libp2p_multiaddr;
use hotshot_types::PeerConfig;
use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashSet, fs};
use timeboost_core::logging;
use timeboost_core::types::metrics::ConsensusMetrics;
use timeboost_core::types::{Keypair, NodeId, PublicKey};
use tokio::signal;
use tracing::warn;

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
    let metrics = Arc::new(ConsensusMetrics::default());
    let mut coordinator = sailfish_coordinator(
        cfg.id,
        cfg.to_connect_addrs,
        cfg.staked_nodes,
        keypair,
        bind_address,
        metrics,
    )
    .await;
    tokio::select! {
        r = coordinator.next() => {
            match r {
                Ok(actions) => {
                    for a in actions {
                        let _res = coordinator.execute(a).await;
                    }
                },
                Err(e) => {
                    tracing::error!("Error: {}", e);
                },
            }
        }
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            coordinator.shutdown().await.expect("Coordinator comm shutdown");
            return Ok(());
        }
    }
    return Ok(());
}
