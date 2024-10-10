mod certificate;
mod constants;
mod message;
mod network_utils;
mod sailfish;
mod tasks;
mod timeout;

use crate::sailfish::Sailfish;
use clap::{Arg, Command};
use hotshot::types::{BLSPrivKey, BLSPubKey, SignatureKey};
use tracing_subscriber::EnvFilter;

fn generate_key_pair(seed: [u8; 32], id: u64) -> (BLSPrivKey, BLSPubKey) {
    let private_key = BLSPubKey::generated_from_seed_indexed(seed, id).1;
    let public_key = BLSPubKey::from_private(&private_key);
    (private_key, public_key)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    if std::env::var("RUST_LOG_FORMAT") == Ok("json".to_string()) {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    // TODO: Derive these from somewhere else
    let (private_key, public_key) = generate_key_pair([0u8; 32], 0);
    let mut sailfish = Sailfish::new(public_key, private_key);

    // Create the command-line arguments
    let matches = Command::new("sailfish")
        .arg(
            Arg::new("id")
                .long("id")
                .value_name("ID")
                .help("The ID of the node that we're running.")
                .required(true),
        )
        .get_matches();

    let id = matches
        .get_one::<u64>("id")
        .expect("Node ID is required (for now).");

    sailfish.run().await;
}
