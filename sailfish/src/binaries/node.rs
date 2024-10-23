use anyhow::Result;
use clap::Parser;
use hotshot::types::BLSPubKey;
use hotshot_types::{PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use sailfish::sailfish;
use ::sailfish::{logging, types::NodeId};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, num::NonZeroUsize};

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    config_path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    to_connect_addrs: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<BLSPubKey>>,
    validator_config: ValidatorConfig<BLSPubKey>,
    id: NodeId,
    port: u16,
    network_size: NonZeroUsize,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();
    let cli = Cli::parse();
    let cfg: Config = toml::from_str(&fs::read_to_string(cli.config_path)?)?;
    sailfish::run(cfg.id, cfg.port, cfg.network_size, cfg.to_connect_addrs, cfg.staked_nodes) .await
}
