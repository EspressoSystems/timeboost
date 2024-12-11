pub mod block;
pub mod block_header;
pub mod error;
pub mod event;
pub mod message;
pub mod metrics;
pub mod seqno;
pub mod time;
pub mod transaction;
pub mod vertex;

#[cfg(feature = "test")]
pub mod test;

use core::fmt;

use serde::{Deserialize, Serialize};

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
