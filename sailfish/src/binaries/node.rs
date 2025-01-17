use std::{collections::HashMap, fs, net::{Ipv4Addr, SocketAddr}};

use ::sailfish::sailfish::sailfish_coordinator;
use anyhow::Result;
use clap::Parser;
use multisig::PublicKey;
use serde::{Deserialize, Serialize};
use timeboost_core::types::metrics::SailfishMetrics;
use timeboost_core::types::NodeId;
use timeboost_utils::{types::logging, unsafe_zero_keypair, PeerConfig};
use tokio::signal;
use tracing::warn;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    config_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    to_connect_addrs: HashMap<PublicKey, SocketAddr>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    id: NodeId,
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    let cfg: Config = toml::from_str(&fs::read_to_string(cli.config_path)?)?;
    let keypair = unsafe_zero_keypair(cfg.id);
    let bind_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.port));

    let metrics = SailfishMetrics::default();
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
        r = coordinator.next() =>  match r {
            Ok(actions) => {
                for a in actions {
                    let _res = coordinator.execute(a).await;
                }
            },
            Err(e) => {
                tracing::error!("Error: {}", e);
            },
        },
        _ = signal::ctrl_c() => {
            warn!("received ctrl-c; shutting down");
            coordinator.shutdown().await.expect("Coordinator comm shutdown");
            return Ok(());
        }
    }
    return Ok(());
}
