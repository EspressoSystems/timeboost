use ark_std::rand::Rng;
use thiserror::Error;

use crate::Committee;

/// A Threshold Encryption Scheme.
pub trait ThresholdEncScheme {
    type Committee;
    type PublicKey;
    type CombKey;
    type KeyShare;
    type Plaintext;
    type Ciphertext;
    type DecShare;

    /// Generate the key material for the scheme.
    #[allow(clippy::type_complexity)]
    fn keygen<R: Rng>(
        rng: &mut R,
        committee: &Committee,
    ) -> Result<(Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>), ThresholdEncError>;

    /// Encrypt a `message` using the encryption key `pk`.
    fn encrypt<R: Rng>(
        rng: &mut R,
        committee: &Committee,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, ThresholdEncError>;

    /// Partial decrypt a `ciphertext` using key share `sk`.
    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError>;

    /// Combine a set of `dec_shares` using `comb_key` into a plaintext message.
    fn combine(
        committee: &Committee,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError>;
}

/// Error types for `ThresholdEncScheme`.
#[derive(Error, Debug)]
pub enum ThresholdEncError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Not enough decryption shares")]
    NotEnoughShares,
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
