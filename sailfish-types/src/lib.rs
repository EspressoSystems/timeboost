mod comm;
mod message;
mod payload;
mod round;
mod vertex;

pub use comm::{Comm, CommError};
pub use message::{Action, Evidence, Payload, NextCommittee};
pub use message::{Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage};
pub use payload::DataSource;
pub use round::RoundNumber;
pub use vertex::Vertex;

use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::Indexed;
use serde::{Deserialize, Serialize};

/// The empty type has no values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Empty {}

impl Committable for Empty {
    fn commit(&self) -> Commitment<Self> {
        unreachable!("No value of `Empty` can be constructed.")
    }
}

/// The unit type has a single value.
///
/// This exists, because `committable` has no impl for `()`.
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Unit;

impl Committable for Unit {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Unit").finalize()
    }
}

impl Indexed for Unit {
    type Index = Self;

    fn index(&self) -> Self::Index {
        Unit
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTime(u64);

impl UnixTime {
    pub fn seconds(self) -> u64 {
        self.0
    }
}

impl From<u64> for UnixTime {
    fn from(seconds: u64) -> Self {
        Self(seconds)
    }
}

impl From<UnixTime> for u64 {
    fn from(seconds: UnixTime) -> Self {
        seconds.0
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
