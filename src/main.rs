mod bincode_utils;
mod certificate;
mod constants;
mod membership;
mod message;
mod network_utils;
mod qc;
mod sailfish;
mod signature_key;
mod stake_table;
mod tasks;
mod threshold;
mod timeout;

use crate::sailfish::Sailfish;
use signature_key::{BLSPubKey, SignatureKey};
use tracing_subscriber::EnvFilter;

fn generate_key_pair<KEY: SignatureKey>(
    seed: [u8; 32],
    index: u64,
) -> (<KEY as SignatureKey>::PrivateKey, KEY) {
    let private_key = <KEY as SignatureKey>::generated_from_seed_indexed(seed, index).1;
    let public_key = <KEY as SignatureKey>::from_private(&private_key);
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

    let (private_key, public_key) = generate_key_pair::<BLSPubKey>([0u8; 32], 0);
    let mut sailfish = Sailfish::new(public_key, private_key);

    sailfish.run().await;
}
