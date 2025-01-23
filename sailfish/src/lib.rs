pub mod consensus;
pub mod coordinator;
pub mod metrics;
pub mod rbc;
pub mod sailfish;

// ensure we can treat a `usize` as an `u64` and vice versa:
const _USIZE_EQ_U64: () = assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u64>());
