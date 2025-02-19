use std::io;
use thiserror::Error;

use crate::frame::InvalidHeader;

/// The empty type has no values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Empty {}

/// The various errors that can occur during networking.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Generic I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// The received frame header is not valid.
    #[error("invalid frame header: {0}")]
    InvalidFrameHeader(#[from] InvalidHeader),

    /// The received frame has an unknown type.
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),

    /// The Noise handshake message is not valid.
    #[error("invalid handshake message")]
    InvalidHandshakeMessage,

    /// The total message size exceeds the allowed maximum.
    #[error("message too large")]
    MessageTooLarge,

    /// Generic Noise error.
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),

    /// Deserializing data into a public key failed.
    #[error("failed to convert public key")]
    Key(#[from] multisig::InvalidPublicKey),

    /// An MPSC channel is unexpectedly closed.
    #[error("channel closed")]
    ChannelClosed,

    /// An operation timed out.
    #[error("timeout")]
    Timeout,
}
