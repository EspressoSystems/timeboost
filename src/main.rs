mod qc;
mod signature_key;
mod stake_table;

use crate::signature_key::*;

pub struct Sailfish {
    /// The public key of the sailfish node.
    public_key: BLSPubKey,

    /// The private key of the sailfish node.
    private_key: BLSPrivKey,
}

impl Sailfish {
    pub fn new(public_key: BLSPubKey, private_key: BLSPrivKey) -> Self {
        Sailfish {
            public_key,
            private_key,
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
}
