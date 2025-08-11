//! Timeboost Contract Bindings, Deployer and API bridges.
//!
//! This crate provides Rust bindings and API to interact with smart contracts,

// Include the generated contract bindings
// The build script auto-detects contracts and generates bindings in src/bindings/
pub mod bindings;
pub mod deployer;

// We manually re-export the type here carefully due to alloy's lack of shared type:
// tracking issue: https://github.com/foundry-rs/foundry/issues/10153
pub use bindings::{erc1967proxy::ERC1967Proxy, keymanager::KeyManager};
