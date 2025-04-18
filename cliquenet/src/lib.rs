mod addr;
mod error;
mod frame;
mod metrics;
mod net;
mod tcp;
mod time;

pub mod overlay;

pub use addr::{Address, InvalidAddress};
pub use error::NetworkError;
pub use metrics::NetworkMetrics;
pub use net::Network;
pub use overlay::Overlay;

/// Max. number of bytes for a message (potentially consisting of several frames).
pub const MAX_MESSAGE_SIZE: usize = 5 * 1024 * 1024;
