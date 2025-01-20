use std::io;
use thiserror::Error;

use crate::frame::InvalidHeader;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Empty {}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] InvalidHeader),

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
