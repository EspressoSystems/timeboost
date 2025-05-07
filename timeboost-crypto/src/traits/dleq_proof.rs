use spongefish::{DomainSeparatorMismatch, ProofError};
use thiserror::Error;

/// Proof of Discrete-log Equality Relation:
/// Given a tuple (g, g_hat, h, h_hat) prove that DLOG_{g}(g_hat) == DLOG_{h}(h_hat).
///
/// In the literature, it's also referred as "DH-triple" relation where g is implicitly
/// the group generator, and h=g^y for some y, and the proof is attesting to the Diffie-Hellman
/// triple (g_hat, h, h_hat) = (g^x, g^y, g^{x*y}) for some x.
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
    IOPatternError(#[from] DomainSeparatorMismatch),
}
