mod addr;
mod chan;
mod error;
mod frame;
mod id;
mod net;
mod tcp;
mod time;

#[cfg(feature = "metrics")]
mod metrics;

pub mod overlay;

pub use addr::{Address, AddressableCommittee, InvalidAddress};
pub use error::NetworkError;
pub use id::Id;
pub use net::Network;
pub use overlay::Overlay;

/// Max. number of bytes for a message (potentially consisting of several frames).
pub const MAX_MESSAGE_SIZE: usize = 5 * 1024 * 1024;

/// Max. number of messages to queue for a peer.
pub const PEER_CAPACITY: usize = 256;

/// Network peer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Active peers receive broadcast messages.
    Active,
    /// Passive peers are excluded from broadcasts.
    ///
    /// Note however that passive peers can be addressed directly in
    /// unicast or multicast operations.
    Passive,
}

impl Role {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}
