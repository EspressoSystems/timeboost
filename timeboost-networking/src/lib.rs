// Copyright (c) 2021-2024 Espresso Systems (espressosys.com)
// This file is part of the HotShot repository.

// You should have received a copy of the MIT License
// along with the HotShot repository. If not, see <https://mit-license.org/>.

//! Library for p2p communication

use std::fmt::Display;

use thiserror::Error;

pub mod network;
/// Network logic
pub mod p2p;

/// symbols needed to implement a networking instance over libp2p-netorking
pub mod reexport {
    pub use libp2p::{request_response::ResponseChannel, Multiaddr};
    pub use libp2p_identity::PeerId;
}

/// Errors that can occur in the network
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Multiple errors. Allows us to roll up multiple errors into one.
    #[error("Multiple errors: {0:?}")]
    Multiple(Vec<NetworkError>),

    /// A configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// An error occurred while sending a message
    #[error("Failed to send message: {0}")]
    MessageSendError(String),

    /// An error occurred while receiving a message
    #[error("Failed to receive message: {0}")]
    MessageReceiveError(String),

    /// The feature is unimplemented
    #[error("Unimplemented")]
    Unimplemented,

    /// An error occurred while attempting to listen
    #[error("Listen error: {0}")]
    ListenError(String),

    /// Failed to send over a channel
    #[error("Channel send error: {0}")]
    ChannelSendError(String),

    /// Failed to receive over a channel
    #[error("Channel receive error: {0}")]
    ChannelReceiveError(String),

    /// The network has been shut down and can no longer be used
    #[error("Network has been shut down")]
    ShutDown,

    /// Failed to serialize
    #[error("Failed to serialize: {0}")]
    FailedToSerialize(String),

    /// Failed to deserialize
    #[error("Failed to deserialize: {0}")]
    FailedToDeserialize(String),

    /// Timed out performing an operation
    #[error("Timeout: {0}")]
    Timeout(String),

    /// The network request had been cancelled before it could be fulfilled
    #[error("The request was cancelled before it could be fulfilled")]
    RequestCancelled,

    /// The network was not ready yet
    #[error("The network was not ready yet")]
    NotReadyYet,

    /// Failed to look up a node on the network
    #[error("Node lookup failed: {0}")]
    LookupError(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Topic {
    /// The `Global` topic goes out to all nodes
    Global,
    /// The `Da` topic goes out to only the DA committee
    Da,
}

/// Libp2p topics require a string, so we need to convert our enum to a string
impl Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Topic::Global => write!(f, "global"),
            Topic::Da => write!(f, "DA"),
        }
    }
}
