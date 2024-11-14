use rand::Rng;
use thiserror::Error;

pub trait DleqProofScheme {
    type Parameters;
    type DleqTuple;
    type Scalar;
    type Proof;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, DleqProofError>;

    fn prove<R: Rng>(
        rng: &mut R,
        pp: Self::Parameters,
        tuple: Self::DleqTuple,
        x: Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError>;

    fn verify(pp: Self::Parameters, proof: Self::Proof) -> Result<(), DleqProofError>;
}

/// The error type for `DleqProofScheme` methods.
#[derive(Error, Debug)]
pub enum DleqProofError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
}
