use async_trait::async_trait;
use thiserror::Error;

/// Agreement on Common Subset (ACS).
///
/// An ACS protocol is an interactive protocol, where each party contributes an input,
/// and all honest parties eventually obtain as output the same size-k subset of the inputs.
#[async_trait]
pub trait ACS {
    type AcsId;
    type PartyId;
    type CommitteeId;
    type Proposal: Clone;
    type Subset;

    async fn propose(
        &mut self,
        proposal: Self::Proposal,
        subset_size: usize,
    ) -> Result<Self::AcsId, AcsError>;

    async fn subset<S>(&self, id: &Self::AcsId) -> Option<Result<S, AcsError>>
    where
        S: IntoIterator<Item = (Self::PartyId, Self::Proposal)>;

    fn is_valid(&self, sender: &Self::PartyId, proposal: &Self::Proposal) -> bool;

    fn acs_info(&self, id: &Self::AcsId) -> Option<(Self::CommitteeId, usize)>;
}

/// The error type for `ACS`.
#[derive(Error, Debug)]
pub enum AcsError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Invalid proposal: {0} for predicate: {1}")]
    PredicateError(String, String),
    #[error("Insufficient proposals")]
    NotEnoughProposals,
    #[error("Internal Error: {0}")]
    Internal(String),
}
