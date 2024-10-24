pub mod consensus;
pub mod coordinator;
pub mod logging;
pub mod sailfish;
pub mod types;

// ensure we can treat a `usize` as an `u64` and vice versa:
const _USIZE_EQ_U64: () = assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u64>());
