use anyhow::Result;
use std::{collections::HashSet, fs, num::NonZeroUsize};

use clap::Parser;
use hotshot_types::PeerConfig;
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use sailfish::sailfish::run;
use serde::{Deserialize, Serialize};
use timeboost_core::types::{NodeId, PublicKey};

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
    timeboost_core::logging::init_logging();
    let cli = Cli::parse();
    let cfg: Config = toml::from_str(&fs::read_to_string(cli.config_path)?)?;
    let network_size = NonZeroUsize::new(cfg.staked_nodes.len()).unwrap();
    run(
        cfg.id,
        cfg.port,
        network_size,
        cfg.to_connect_addrs,
        cfg.staked_nodes,
    )
    .await
}
