use std::io;
use thiserror::Error;

use crate::frame::InvalidHeader;

/// The empty type has no values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Empty {}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid frame header: {0}")]
    InvalidFrameHeader(#[from] InvalidHeader),

    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),

    #[error("invalid handshake message")]
    InvalidHandshakeMessage,

    #[error("message too large")]
    MessageTooLarge,

    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),

    #[error("failed to convert public key")]
    Key(#[from] multisig::InvalidPublicKey),

    #[error("channel closed")]
    ChannelClosed,
}
