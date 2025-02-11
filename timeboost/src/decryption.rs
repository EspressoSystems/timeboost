use nimue::DigestBridge;
use sha2::Sha256;
pub use timeboost_crypto::sg_encryption::Keyset;
use timeboost_crypto::sg_encryption::{KeyShare, PublicKey, ShoupGennaro};

// Initialize types for use in Timeboost
type G = ark_secp256k1::Projective;
type H = Sha256;
type D = DigestBridge<H>;

pub type DecryptionScheme = ShoupGennaro<G, H, D>;

pub type CombKey = PublicKey<G>;
pub type DecShare = KeyShare<G>;

#[derive(Clone)]
pub struct TrustedKeygenResult {
    pub public_key: CombKey,
    pub key_shares: Vec<DecShare>,
}

impl TrustedKeygenResult {
    pub fn new(public_key: CombKey, key_shares: Vec<DecShare>) -> Self {
        TrustedKeygenResult {
            public_key,
            key_shares,
        }
    }
}
