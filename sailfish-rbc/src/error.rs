use cliquenet::overlay::{DataError, NetworkDown};
use sailfish_types::RoundNumber;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RbcError {
    #[error("data error: {0}")]
    DataError(#[from] DataError),

    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::error::EncodeError),

    #[error("deserialization error: {0}")]
    Deserialization(#[from] bincode::error::DecodeError),

    #[error("invalid message")]
    InvalidMessage,

    #[error("invalid sender")]
    InvalidSender,

    #[error("no committee for round {0}")]
    NoCommittee(RoundNumber),

    #[error("rbc has shut down")]
    Shutdown,
}

impl From<NetworkDown> for RbcError {
    fn from(_: NetworkDown) -> Self {
        Self::Shutdown
    }
}
