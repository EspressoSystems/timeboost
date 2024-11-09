use rand::Rng;
use thiserror::Error;

pub trait ThresholdEncScheme {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type Randomness;
    type Plaintext;
    type Ciphertext;
    type DecShare;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, ThresholdEncError>;

    fn keygen<R: Rng>(
        params: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), ThresholdEncError>;

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ThresholdEncError>;

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
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
