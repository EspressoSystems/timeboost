//! Traits related to Distributed Key Generation (DKG) and Key Resharing

use ark_std::rand::Rng;
use std::ops::Add;
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

    /// Verifies a secret share against the commitment.
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
        shares: impl ExactSizeIterator<Item = (usize, Self::SecretShare)> + Clone,
    ) -> Result<Self::Secret, VssError>;

    /// Aggregates multiple commitments and secret shares into a single commitment and secret share.
    ///
    /// This is commonly used in DKG protocols to combine multiple dealings/contributions.
    ///
    /// Returns `Ok((secret_share, commitment))` if aggregation succeeds
    fn aggregate<I>(dealings: I) -> Result<(Self::SecretShare, Self::Commitment), VssError>
    where
        I: Iterator<Item = (Self::SecretShare, Self::Commitment)>,
        Self::Commitment: Add<Self::Commitment, Output = Self::Commitment>,
        Self::SecretShare: Add<Self::SecretShare, Output = Self::SecretShare>,
    {
        dealings
            .reduce(|(acc_share, acc_comm), (share, comm)| (acc_share + share, acc_comm + comm))
            .ok_or(VssError::EmptyAggInput)
    }
}

/// Publicly verifiable key resharing scheme for a VSS where existing share holders of a Shamir
/// secret sharing can create a new Shamir secret sharing of the same secret and distribute it to a
/// set of receivers in a confidential, yet verifiable manner.
///
/// # Notation
///
/// Resharing from (t,n) to (t', n') committee, all the reshares are arranged in a (n x n') matrix
/// each row is a resharing dealing containing n' reshares, sent by Party i \in [n];
/// each row is accompanied by a row_commitment
/// each col is reshares received by a Party j' \in [n'].
///
/// `reshare()` invoked by Party i outputs the i-th row of (n x n')-matrix, and i-th row_commitment
/// `verify_reshare()` invoked by anyone to verify (i,j)-cell
/// `combine()` invoked by Parth j', takes a subset of rows in the matrix and their row commitments
/// and outputs j'-th new secret share and new commitment
pub trait KeyResharing<VSS: VerifiableSecretSharing> {
    /// Given the new public parameter (t', n'), and holding secret share,
    /// generates a dealing (resharing of a share) for the new VSS set/committee
    fn reshare<R: Rng>(
        new_pp: &VSS::PublicParam,
        old_share: &VSS::SecretShare,
        rng: &mut R,
    ) -> (Vec<VSS::SecretShare>, VSS::Commitment);

    /// Publicly verify the correctness of a reshare
    fn verify_reshare(
        old_pp: &VSS::PublicParam,
        new_pp: &VSS::PublicParam,
        send_node_idx: usize,
        recv_node_idx: usize,
        old_commitment: &VSS::Commitment,
        row_commitment: &VSS::Commitment,
        reshare: &VSS::SecretShare,
    ) -> Result<(), VssError>;

    /// Combine resharings to derive the new secret share
    fn combine(
        old_pp: &VSS::PublicParam,
        new_pp: &VSS::PublicParam,
        recv_node_idx: usize,
        reshares: impl Iterator<Item = (usize, VSS::SecretShare, VSS::Commitment)>,
    ) -> Result<(VSS::Secret, VSS::Commitment), VssError>;
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
    #[error("aggregation input is empty")]
    EmptyAggInput,

    #[error("reshare data is empty")]
    EmptyReshare,
    #[error("input length mismatched")]
    MismatchedInputLength,
    #[error("failed to combine reshares: {0}")]
    FailedCombine(String),
}
