mod certificate;
mod constants;
mod logging;
mod message;
mod network_utils;
mod sailfish;
mod tasks;
mod timeout;

use clap::Parser;
use hotshot::types::{BLSPubKey, SignatureKey};
use libp2p_identity::PeerId;
use libp2p_networking::reexport::Multiaddr;
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
    id: u64,
    network_size: usize,
}

#[tokio::main]
async fn main() {
    logging::init_logging();

    let cli = Cli::parse();
    let config: Config =
        toml::from_str(&fs::read_to_string(cli.config_path).expect("Failed to read config file"))
            .expect("Failed to parse config file");

    sailfish::initialize_and_run_sailfish(config.id, config.network_size, config.to_connect_addrs)
        .await;
}
