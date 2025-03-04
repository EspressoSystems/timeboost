use cliquenet::Address;

pub mod types;

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    sig_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn sig_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(new_seed)
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

pub fn dec_addr(addr: &Address) -> Address {
    let mut dec_addr = addr.clone();
    dec_addr.set_port(addr.port() + 250);
    dec_addr
}
