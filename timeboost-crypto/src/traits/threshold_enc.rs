use std::collections::BTreeSet;

use ark_std::rand::Rng;
use thiserror::Error;

use crate::traits::dleq_proof::DleqProofError;
use crate::{Keyset, KeysetId};

/// A Threshold Encryption Scheme.
pub trait ThresholdEncScheme {
    type Committee;
    type PublicKey;
    type CombKey;
    type KeyShare;
    type Plaintext;
    // see <https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data>
    type AssociatedData;
    type Ciphertext;
    type DecShare;

    /// Generate the key material for the scheme.
    #[allow(clippy::type_complexity)]
    fn keygen<R: Rng>(
        rng: &mut R,
        committee: &Keyset,
    ) -> Result<(Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>), ThresholdEncError>;

    /// Encrypt a `message` using the encryption key `pk`.
    fn encrypt<R: Rng>(
        rng: &mut R,
        kid: &KeysetId,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Ciphertext, ThresholdEncError>;

    /// Partial decrypt a `ciphertext` using key share `sk`.
    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::DecShare, ThresholdEncError>;

    /// Combine a set of `dec_shares` using `comb_key` into a plaintext message.
    fn combine(
        committee: &Keyset,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Plaintext, ThresholdEncError>;
}

/// Error types for `ThresholdEncScheme`.
#[derive(Error, Debug)]
pub enum ThresholdEncError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Not enough decryption shares")]
    NotEnoughShares,
    #[error(transparent)]
    DleqError(DleqProofError),
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Faulty node indices: {0:?}")]
    FaultySubset(BTreeSet<u32>),
}
