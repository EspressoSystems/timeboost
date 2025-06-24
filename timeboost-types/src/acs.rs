use async_trait::async_trait;
use thiserror::Error;

/// Agreement on Common Subset (ACS).
///
/// An ACS protocol is an interactive protocol where each party contributes an input,
/// and all honest parties eventually obtain as output the same size-k subset of the inputs.
#[async_trait]
pub trait Acs {
    /// ID of the current instance of ACS.
    type AcsId;
    /// Public identifier of a node.
    type NodeId;
    /// Committee executing the ACS instance.
    type CommitteeId;
    /// A concrete proposal subject to ACS.
    type Proposal: Clone;

    /// Proposes a new `proposal` value for ACS with a subset of size `subset_size`.
    async fn propose(
        &mut self,
        proposal: Self::Proposal,
        subset_size: usize,
    ) -> Result<Self::AcsId, AcsError>;

    /// Retrieves the subset of proposals agreed upon for a given ACS instance.
    async fn subset<S>(&self, id: &Self::AcsId) -> Option<Result<S, AcsError>>
    where
        S: IntoIterator<Item = (Self::NodeId, Self::Proposal)>;

    /// Evaluates the validity of a proposal.
    fn is_valid(&self, sender: &Self::NodeId, proposal: &Self::Proposal) -> bool;

    /// Extracts information about a specific ACS instance.
    fn acs_info(&self, id: &Self::AcsId) -> Option<(Self::CommitteeId, usize)>;
}

/// The error type for ACS.
#[derive(Error, Debug)]
pub enum AcsError {
    #[error("Invalid argument: {0}")]
    Argument(String),
    #[error("Invalid proposal: {0} for predicate: {1}")]
    PredicateError(String, String),
    #[error("Insufficient proposals")]
    NotEnoughProposals,
    #[error("Internal error: {0}")]
    Internal(String),
}
