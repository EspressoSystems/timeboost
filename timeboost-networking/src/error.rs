use std::io;
use thiserror::Error;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Empty {}

/// Errors that can occur in the network
#[derive(Debug, Error)]
pub enum NetworkError {
    /// I/O error
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("frame len {0} is too large")]
    FrameTooLarge(usize),

    /// A noise error
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),

    #[error("failed to convert public key")]
    Key(#[from] multisig::InvalidPublicKey),

    #[error("channel closed")]
    ChannelClosed,
}

