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
