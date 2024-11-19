pub mod block;
pub mod block_header;
pub mod certificate;
pub mod committee;
pub mod envelope;
pub mod error;
pub mod event;
pub mod message;
pub mod metrics;
pub mod round_number;
pub mod seqno;
pub mod time;
pub mod transaction;
pub mod vertex;

#[cfg(feature = "test")]
pub mod test;

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

#[derive(Clone)]
pub struct Keypair {
    private: PrivateKey,
    public: PublicKey,
}

impl Keypair {
    pub const ZERO_SEED: [u8; 32] = [0; 32];

    pub fn new<N: Into<u64>>(index: N) -> Self {
        let seed = rand::random();
        let (p, s) = PublicKey::generated_from_seed_indexed(seed, index.into());
        Self {
            private: s,
            public: p,
        }
    }

    pub fn random() -> Self {
        let seed = rand::random();
        let index = rand::random();
        let (public, private) = PublicKey::generated_from_seed_indexed(seed, index);
        Self { private, public }
    }

    #[cfg(feature = "test")]
    pub fn zero<N: Into<u64>>(index: N) -> Self {
        let (p, s) = PublicKey::generated_from_seed_indexed(Self::ZERO_SEED, index.into());
        Self {
            private: s,
            public: p,
        }
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        PublicKey::sign(self.private_key(), data).expect("BLS signing never fails")
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Clone, Copy)]
pub struct Label(u64);

impl Label {
    pub fn new<H: std::hash::Hash>(x: H) -> Self {
        use std::hash::Hasher;
        let mut h = std::hash::DefaultHasher::new();
        x.hash(&mut h);
        Self(h.finish())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L{:X}", self.0)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
