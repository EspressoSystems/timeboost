use async_trait::async_trait;
use thiserror::Error;

/// Agreement on Common Subset (ACS).
///
/// An ACS protocol is an interactive protocol, where each party contributes an input,
/// and all honest parties eventually obtain as output the same size-k subset of the inputs.
#[async_trait]
pub trait ACS {
    /// Input proposal.
    type Proposal;
    /// Validity predicate for validating incoming proposals.
    type Predicate;
    /// Agreed-upon subset of proposals.
    type Subset;

    /// Submit a `proposal` and expect as result an agreed-upon size-`k` subset of
    /// proposals which satifies `predicate`.
    async fn propose(
        self,
        proposal: Self::Proposal,
        predicate: Self::Predicate,
        k: u32,
    ) -> Result<Self::Subset, ACSError>;
}

/// The error type for `ACS`.
#[derive(Error, Debug)]
pub enum ACSError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Invalid proposal: {0} for predicate: {1}")]
    PredicateError(String, String),
    #[error("Insufficient proposals")]
    NotEnoughProposals,
    #[error("Internal Error: {0}")]
    Internal(anyhow::Error),
}
