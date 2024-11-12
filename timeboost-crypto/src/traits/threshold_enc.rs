use rand::Rng;
use thiserror::Error;

pub trait ThresholdEncScheme {
    type Committee;
    type Parameters;
    type PublicKey;
    type KeyShare;
    type Randomness;
    type Plaintext;
    type Ciphertext;
    type DecShare;

    fn setup<R: Rng>(
        committee: Self::Committee,
        rng: &mut R,
    ) -> Result<Self::Parameters, ThresholdEncError>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Vec<Self::KeyShare>), ThresholdEncError>;

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ThresholdEncError>;

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError>;

    fn combine(
        pp: &Self::Parameters,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError>;
}

/// The error type for `ThresholdEncScheme` methods.
#[derive(Error, Debug)]
pub enum ThresholdEncError {
    #[error("Invalid argument {0:?})")]
    Argument(String),
    #[error("Not enough decryption shares")]
    NotEnoughShares,
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
}
