use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_crypto::{
    sg_encryption::{CombKey, Committee, KeyShare, PublicKey, ShoupGennaro},
    D, G, H,
};
pub mod traits;
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

/// Trusted Keygen Outputs
/// - One distinct private key (one group element) per node for partial decryption.
/// - A single public key for clients to encrypt their transaction bundles.
/// - The same combination key to all node for combining partial decrypted ciphertexts.
pub fn thres_enc_keygen(size: u32) -> (PublicKey<G>, CombKey<G>, Vec<KeyShare<G>>) {
    // TODO: fix committee id when dynamic keysets
    let mut rng = ark_std::rand::thread_rng();
    let committee = Committee { id: 0, size };
    let parameters = ShoupGennaro::<G, H, D>::setup(&mut rng, committee).unwrap();
    ShoupGennaro::<G, H, D>::keygen(&mut rng, &parameters).unwrap()
}
