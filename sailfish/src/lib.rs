mod coordinator;

pub use committable;
pub use sailfish_consensus as consensus;
pub use sailfish_rbc as rbc;
pub use sailfish_types as types;

pub use coordinator::Coordinator;

// ensure we can treat a `usize` as an `u64` and vice versa:
const _USIZE_EQ_U64: () = assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u64>());
