mod consensus;
mod coordinator;
mod metrics;
mod rbc;
mod sailfish;

// ensure we can treat a `usize` as an `u64` and vice versa:
const _USIZE_EQ_U64: () = assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u64>());

pub use consensus::{Consensus, Dag};
pub use coordinator::Coordinator;
pub use metrics::SailfishMetrics;
pub use rbc::{Rbc, RbcConfig, RbcMetrics};
pub use sailfish::setup;
