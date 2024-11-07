use anyhow::Result;
use clap::Parser;
use hotshot_types::PeerConfig;
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use multiaddr::multiaddr;
use sailfish::sailfish;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs};
use timeboost_core::logging;
use timeboost_core::types::{Keypair, NodeId, PublicKey};

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
    let bind_address = multiaddr!(Ip4([0, 0, 0, 0]), Tcp(cfg.port));
    sailfish::run_sailfish(
        cfg.id,
        cfg.to_connect_addrs,
        cfg.staked_nodes,
        keypair,
        bind_address,
    )
    .await
}
