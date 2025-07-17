//! Traits related to Distributed Key Generation (DKG) and Key Resharing

use ark_std::rand::Rng;
use thiserror::Error;

/// A trait for (t, n)-Verifiable Secret Sharing (VSS) schemes.
/// See: <https://en.wikipedia.org/wiki/Verifiable_secret_sharing>
///
/// Note: We avoid using const generics for `(t, n)` to support scenarios where
/// these parameters are determined at runtime. While const generics offer stronger
/// type-level guarantees, they require compile-time constants, which would limit flexibility.
pub trait VerifiableSecretSharing {
    /// system parameters such as t, n, sometimes common reference string for PCS-based VSS
    type PublicParam;
    type Secret;
    type SecretShare;
    type Commitment;

    /// Generates a (t, n)-secret sharing of the given `secret`.
    ///
    /// System parameters like threshold t and total nodes n are in `pp`.
    ///
    /// Returns a tuple of:
    ///   - a vector of `n` secret shares,
    ///   - a global proof/commitment (e.g., Feldman commitments; may be unused in some schemes),
    fn share<R: Rng>(
        pp: &Self::PublicParam,
        rng: &mut R,
        // TODO(alex): consider accept Zeroizing<Self::Secret> instead
        secret: Self::Secret,
    ) -> (Vec<Self::SecretShare>, Self::Commitment);

    /// Verifies a secret share against the global and per-share proofs.
    ///
    /// - `node_idx`: index of the share to verify
    /// - `share`: the secret share to verify
    /// - `commitment`: the global commitment (if any)
    ///
    /// Returns Ok(()) if valid, or an appropriate `VssError` otherwise.
    fn verify(
        pp: &Self::PublicParam,
        node_idx: usize,
        share: &Self::SecretShare,
        commitment: &Self::Commitment,
    ) -> Result<(), VssError>;

    /// Reconstructs the original secret from a set of (index, share) pairs.
    ///
    /// System parameters like threshold t and total nodes n are in `pp`.
    ///
    /// Returns `Ok(secret)` if reconstruction succeeds, or an appropriate `VssError` otherwise.
    fn reconstruct(
        pp: &Self::PublicParam,
        shares: impl Iterator<Item = (usize, Self::SecretShare)>,
    ) -> Result<Self::Secret, VssError>;
}

/// Error types for [`VerifiableSecretSharing`]
#[derive(Error, Debug, Clone)]
pub enum VssError {
    #[error("mismatched number of secret shares, expected: {0}, got: {1}")]
    MismatchedSharesCount(usize, usize),
    #[error("share index out of bound, max: {0}, got: {1}")]
    IndexOutOfBound(usize, usize),
    #[error("invalid secret share at index {0}: {1}")]
    InvalidShare(usize, String),
    #[error("invalid VSS commitment")]
    InvalidCommitment,
    #[error("failed verification: share does not match commitment")]
    FailedVerification,
    #[error("failed to reconstruct: {0}")]
    FailedReconstruction(String),
    #[error("internal err: {0}")]
    InternalError(String),
}
