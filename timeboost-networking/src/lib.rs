// Copyright (c) 2021-2024 Espresso Systems (espressosys.com)
// This file is part of the HotShot repository.

// You should have received a copy of the MIT License
// along with the HotShot repository. If not, see <https://mit-license.org/>.

use std::{
    fmt::Display,
    net::{IpAddr, ToSocketAddrs},
};

use anyhow::{anyhow, Context};
use libp2p_identity::{
    ed25519::{self, SecretKey},
    Keypair, PeerId,
};
use multiaddr::Multiaddr;
use thiserror::Error;
use timeboost_crypto::traits::signature_key::{PrivateSignatureKey, SignatureKey};
use tracing::warn;
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

/// Parse a Libp2p Multiaddr from a string. The input string should be in the format
/// `hostname:port` or `ip:port`. This function derives a `Multiaddr` from the input string.
///
/// This borrows from Rust's implementation of `to_socket_addrs` but will only warn if the domain
/// does not yet resolve.
///
/// # Errors
/// - If the input string is not in the correct format
pub fn derive_multiaddr(addr: &String) -> anyhow::Result<Multiaddr> {
    // Split the address into the host and port parts
    let (host, port) = match addr.rfind(':') {
        Some(idx) => (&addr[..idx], &addr[idx + 1..]),
        None => return Err(anyhow!("Invalid address format, no port supplied")),
    };

    // Try parsing the host as an IP address
    let ip = host.parse::<IpAddr>();

    // Conditionally build the multiaddr string
    let multiaddr_string = match ip {
        Ok(IpAddr::V4(ip)) => format!("/ip4/{ip}/udp/{port}/quic-v1"),
        Ok(IpAddr::V6(ip)) => format!("/ip6/{ip}/udp/{port}/quic-v1"),
        Err(_) => {
            // Try resolving the host. If it fails, continue but warn the user
            let lookup_result = addr.to_socket_addrs();

            // See if the lookup failed
            let failed = lookup_result
                .map(|result| result.collect::<Vec<_>>().is_empty())
                .unwrap_or(true);

            // If it did, warn the user
            if failed {
                warn!(
                    "Failed to resolve domain name {}, assuming it has not yet been provisioned",
                    host
                );
            }

            format!("/dns/{host}/udp/{port}/quic-v1")
        }
    };

    // Convert the multiaddr string to a `Multiaddr`
    multiaddr_string.parse().with_context(|| {
        format!("Failed to convert Multiaddr string to Multiaddr: {multiaddr_string}",)
    })
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
