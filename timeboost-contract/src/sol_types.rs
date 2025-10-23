//! Solidity types for contract interaction

// We manually re-export the type here carefully due to alloy's lack of shared type:
// tracking issue: https://github.com/foundry-rs/foundry/issues/10153
pub use crate::bindings::{
    r#erc1967proxy::ERC1967Proxy,
    r#keymanager::KeyManager,
    r#keymanager::KeyManager::{Committee as CommitteeSol, CommitteeMember as CommitteeMemberSol},
};

impl CommitteeMemberSol {
    #[cfg(test)]
    pub fn random() -> Self {
        use alloy::primitives::Bytes;
        use rand::prelude::*;

        let mut rng = rand::rng();
        CommitteeMemberSol {
            sigKey: Bytes::from(rng.random::<[u8; 32]>()),
            dhKey: Bytes::from(rng.random::<[u8; 32]>()),
            dkgKey: Bytes::from(rng.random::<[u8; 32]>()),
            networkAddress: format!("127.0.0.1:{}", rng.random::<u16>()),
        }
    }
}
