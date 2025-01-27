use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
};

use ::sailfish::sailfish::sailfish_coordinator;
use anyhow::Result;
use clap::Parser;
use multisig::PublicKey;
use sailfish::metrics::SailfishMetrics;
use serde::{Deserialize, Serialize};
use timeboost_core::types::NodeId;
use timeboost_networking::metrics::NetworkMetrics;
use timeboost_utils::{types::logging, unsafe_zero_keypair};
use tokio::signal;
use tracing::warn;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    config_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    to_connect_addrs: Vec<(PublicKey, SocketAddr)>,
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

    let sf_metrics = SailfishMetrics::default();
    let net_metrics = NetworkMetrics::default();
    let mut coordinator = sailfish_coordinator(
        cfg.id,
        cfg.to_connect_addrs,
        keypair,
        bind_address,
        sf_metrics,
        net_metrics,
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
            return Ok(());
        }
    }
    return Ok(());
}
