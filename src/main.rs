mod bincode_utils;
mod certificate;
mod constants;
mod membership;
mod message;
mod qc;
mod signature_key;
mod stake_table;
mod threshold;
mod timeout;

use crate::{
    constants::{EXTERNAL_EVENT_CHANNEL_SIZE, INTERNAL_EVENT_CHANNEL_SIZE},
    message::*,
    signature_key::*,
};
use async_broadcast::{broadcast, InactiveReceiver, Receiver, Sender};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

pub struct Sailfish {
    /// The public key of the sailfish node.
    public_key: BLSPubKey,

    /// The private key of the sailfish node.
    private_key: BLSPrivKey,

    /// The sender of the sailfish node.
    internal_event_stream: (Sender<Arc<SailfishMessage>>, Receiver<Arc<SailfishMessage>>),
}

impl Sailfish {
    pub fn new(public_key: BLSPubKey, private_key: BLSPrivKey) -> Self {
        Sailfish {
            public_key,
            private_key,
            internal_event_stream: broadcast(INTERNAL_EVENT_CHANNEL_SIZE),
        }
    }

    pub fn run(&self) {
        tracing::info!("Starting Sailfish");
    }
}

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
    let sailfish = Sailfish::new(public_key, private_key);

    sailfish.run();
}
