use hotshot::types::{BLSPrivKey, BLSPubKey, SignatureKey};
use serde::{Deserialize, Serialize};

pub mod block;
pub mod block_header;
pub mod certificate;
pub mod comm;
pub mod envelope;
pub mod message;
pub mod vertex;

pub type PublicKey = BLSPubKey;
pub type SecretKey = BLSPrivKey;
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
