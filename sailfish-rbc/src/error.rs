#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RbcError {
    #[error("network error: {0}")]
    Net(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::error::EncodeError),

    #[error("deserialization error: {0}")]
    Deserialization(#[from] bincode::error::DecodeError),

    #[error("invalid message")]
    InvalidMessage,

    #[error("invalid sender")]
    InvalidSender,

    #[error("rbc has shut down")]
    Shutdown,
}

impl RbcError {
    pub(crate) fn net<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Net(Box::new(e))
    }
}
