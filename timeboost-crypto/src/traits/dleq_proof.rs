use nimue::{IOPatternError, ProofError};
use thiserror::Error;

pub trait DleqProofScheme {
    type DleqTuple;
    type Scalar;
    type Proof;

    fn prove(tuple: Self::DleqTuple, x: &Self::Scalar) -> Result<Self::Proof, DleqProofError>;

    fn verify(tuple: Self::DleqTuple, proof: &Self::Proof) -> Result<(), DleqProofError>;
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
    #[error(transparent)]
    ProofError(#[from] ProofError),
    #[error(transparent)]
    IOPatternError(#[from] IOPatternError),
}
