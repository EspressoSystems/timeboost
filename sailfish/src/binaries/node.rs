use clap::Parser;
use hotshot::types::BLSPubKey;
use hotshot_types::{data::ViewNumber, PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
use sailfish::logging;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs};

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
    id: u64,
    network_size: usize,
    gc_depth: ViewNumber,
}

#[tokio::main]
async fn main() {
    logging::init_logging();

    let cli = Cli::parse();
    let config: Config =
        toml::from_str(&fs::read_to_string(cli.config_path).expect("Failed to read config file"))
            .expect("Failed to parse config file");

    sailfish::sailfish::initialize_and_run_sailfish(
        config.id,
        config.network_size,
        config.to_connect_addrs,
        config.staked_nodes,
        config.validator_config,
        config.gc_depth,
    )
    .await;
}
