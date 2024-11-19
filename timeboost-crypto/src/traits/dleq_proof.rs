use rand::Rng;
use thiserror::Error;

pub trait DleqProofScheme {
    type Parameters;
    type DleqTuple;
    type Scalar;
    type Proof;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, DleqProofError>;

    fn prove(
        pp: &Self::Parameters,
        tuple: Self::DleqTuple,
        x: &Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError>;

    fn verify(
        pp: &Self::Parameters,
        tuple: Self::DleqTuple,
        proof: &Self::Proof,
    ) -> Result<(), DleqProofError>;
}

/// The error type for `DleqProofScheme` methods.
#[derive(Error, Debug)]
pub enum DleqProofError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Invalid proof")]
    ProofNotValid,
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
}
