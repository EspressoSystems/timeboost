mod comm;
mod message;
mod payload;
mod round;
mod vertex;

pub use comm::{Comm, CommError};
pub use message::{Action, Evidence, Payload};
pub use message::{Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage};
pub use payload::DataSource;
pub use round::RoundNumber;
pub use vertex::Vertex;

use committable::{Commitment, Committable, RawCommitmentBuilder};
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
