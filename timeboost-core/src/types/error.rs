use serde::{Deserialize, Serialize};
use thiserror::Error;
use timeboost_utils::types::round_number::RoundNumber;

/// An error that can occur in the Sailfish protocol that timeboost would want to know about.
///
/// In particular, it is relevant to know about:
/// - Invalid signatures, as this would potentially imply an issue with a received bundle.
/// - Missing vertices, as this would imply that we may be missing data that we need in
///   order to build our block.
/// - Serialization failures, as this would imply an issue with our own serialization
///   routines.
/// - Timeouts, as this would imply that we are not making progress in the protocol.
///
/// The application layer is responsible for reporting this information, but consensus is
/// responsible for sending it at the appropriate interval.
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SailfishError {
    /// When the signature of a vertex is invalid.
    #[error("Invalid signature with commitment: {commitment}")]
    InvalidSignature { commitment: String },

    /// When a vertex is missing in storage. This happens when we are trying
    /// to utilize a vertex bundle that is somehow not available, but needs to
    /// be for the purposes of building our block.
    ///
    /// This would typically happen if we GC some old data erroneously.
    #[error("Missing vertex with commitment: {commitment}")]
    MissingVertex { commitment: String },

    /// A serialization failure occurred (i.e. for a block, tx, etc).
    /// This gives the name of the data or some type of descriptor.
    /// This error can occur when serializing or deserializing data.
    #[error("Serialization failure: {0}")]
    SerializationFailure(String),

    /// A timeout has occurred.
    #[error("Timeout: {round} {stage:?}")]
    Timeout {
        round: RoundNumber,
        stage: RoundTimeoutStage,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoundTimeoutStage {
    /// The timeout occurred during the prepare phase.
    Prepare,

    /// The timeout occurred during the propose phase.
    Propose,

    /// The timout occurred during the "vote" phase.
    Vote,

    /// The timeout occurred during the commit phase.
    Commit,
}
