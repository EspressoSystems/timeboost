use libp2p_identity::{
    ed25519::{self, SecretKey},
    Keypair, PeerId,
};
use thiserror::Error;
use timeboost_crypto::traits::signature_key::{PrivateSignatureKey, SignatureKey};
pub mod network;

/// Derive a Libp2p keypair from a given private key
///
/// # Errors
/// If we are unable to derive a new `SecretKey` from the `blake3`-derived
/// bytes.
pub fn derive_keypair<K: SignatureKey>(private_key: &K::PrivateKey) -> anyhow::Result<Keypair> {
    // Derive a secondary key from our primary private key
    let derived_key = blake3::derive_key("libp2p key", &private_key.to_bytes());
    let derived_key = SecretKey::try_from_bytes(derived_key)?;

    // Create an `ed25519` keypair from the derived key
    Ok(ed25519::Keypair::from(derived_key).into())
}

/// Derive a Libp2p Peer ID from a given private key
///
/// # Errors
/// If we are unable to derive a Libp2p keypair
pub fn derive_peer_id<K: SignatureKey>(private_key: &K::PrivateKey) -> anyhow::Result<PeerId> {
    // Get the derived keypair
    let keypair = derive_keypair::<K>(private_key)?;

    // Return the PeerID derived from the public key
    Ok(PeerId::from_public_key(&keypair.public()))
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

    /// Failed to serialize
    #[error("Failed to serialize: {0}")]
    FailedToCompleteNoiseHandshake(String),

    /// Timed out performing an operation
    #[error("Timeout: {0}")]
    Timeout(String),

    /// The network request had been cancelled before it could be fulfilled
    #[error("The request was cancelled before it could be fulfilled")]
    RequestCancelled,

    /// The network was not ready yet
    #[error("The network was not ready yet")]
    NotReadyYet,

    /// The cannot set no delay
    #[error("The stream was not able to set no delay")]
    SetNoDelayFailure,

    /// Failed to look up a node on the network
    #[error("Node lookup failed: {0}")]
    LookupError(String),
}
