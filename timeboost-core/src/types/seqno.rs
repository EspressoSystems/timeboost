use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Sequence number.
//
// TODO: Is a `u128` required here?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SeqNo(u128);

impl From<u128> for SeqNo {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<SeqNo> for u128 {
    fn from(value: SeqNo) -> Self {
        value.0
    }
}

impl Deref for SeqNo {
    type Target = u128;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
