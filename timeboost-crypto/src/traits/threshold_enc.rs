use ark_serialize::SerializationError;
use rand::Rng;
use thiserror::Error;

pub trait ThresholdEncScheme {
    type Committee;
    type Parameters;
    type PublicKey;
    type KeyShare;
    type Plaintext;
    type Ciphertext;
    type DecShare;

    fn setup<R: Rng>(
        rng: &mut R,
        committee: Self::Committee,
    ) -> Result<Self::Parameters, ThresholdEncError>;

    fn keygen<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PublicKey, Vec<Self::KeyShare>), ThresholdEncError>;

    fn encrypt<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, ThresholdEncError>;

    fn decrypt<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError>;

    fn combine(
        pp: &Self::Parameters,
        pub_key: &Self::PublicKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError>;
}

/// The error type for `ThresholdEncScheme` methods.
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
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
