//! Solidity types for contract interaction

use alloy::primitives::Bytes;
use rand::prelude::*;

// We manually re-export the type here carefully due to alloy's lack of shared type:
// tracking issue: https://github.com/foundry-rs/foundry/issues/10153
pub use crate::bindings::{
    erc1967proxy::ERC1967Proxy,
    keymanager::KeyManager,
    keymanager::KeyManager::{Committee as CommitteeSol, CommitteeMember as CommitteeMemberSol},
};

impl CommitteeMemberSol {
    pub fn random() -> Self {
        let mut rng = rand::rng();
        CommitteeMemberSol {
            sigKey: Bytes::from(rng.random::<[u8; 32]>()),
            dhKey: Bytes::from(rng.random::<[u8; 32]>()),
            dkgKey: Bytes::from(rng.random::<[u8; 32]>()),
            networkAddress: format!("127.0.0.1:{}", rng.random::<u16>()),
        }
    }
}
