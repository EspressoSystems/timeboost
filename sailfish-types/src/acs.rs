use async_trait::async_trait;
use thiserror::Error;

/// Agreement on Common Subset (ACS).
///
/// An ACS protocol is an interactive protocol, where each party contributes an input,
/// and all honest parties eventually obtain as output the same size-k subset of the inputs.
#[async_trait]
pub trait Acs {
    /// Id of the current instance of Acs.
    type AcsId;
    /// Public identifier of the a node.
    type NodeId;
    /// Committee executing the Acs instance.
    type CommitteeId;
    /// A concrete proposal subject to Acs.
    type Proposal: Clone;
    /// A resulting subset output of Acs.
    type Subset;

    /// Proposes a new `proposal` for Acs with subset of size `subset_size`.
    async fn propose(
        &mut self,
        proposal: Self::Proposal,
        subset_size: usize,
    ) -> Result<Self::AcsId, AcsError>;

    /// Retrieves the subset of proposals agreed upon for a given ACS instance.
    async fn subset<S>(&self, id: &Self::AcsId) -> Option<Result<S, AcsError>>
    where
        S: IntoIterator<Item = (Self::NodeId, Self::Proposal)>;

    /// Method for evaluating validity of the proposal.
    fn is_valid(&self, sender: &Self::NodeId, proposal: &Self::Proposal) -> bool;

    /// Extracts information of the specific ACS instance.
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
