pub mod block;
pub mod block_header;
pub mod certificate;
pub mod committee;
pub mod envelope;
pub mod error;
pub mod event;
pub mod message;
pub mod round_number;
pub mod vertex;

use core::fmt;

use hotshot::types::{BLSPrivKey, BLSPubKey, SignatureKey};
use serde::{Deserialize, Serialize};

pub type PublicKey = BLSPubKey;
pub type PrivateKey = BLSPrivKey;
pub type Signature = <PublicKey as SignatureKey>::PureAssembledSignatureType;
pub type QuorumSignature = <PublicKey as SignatureKey>::QcType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(u64);

impl From<u64> for NodeId {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<NodeId> for u64 {
    fn from(val: NodeId) -> Self {
        val.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
