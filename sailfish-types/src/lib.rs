mod comm;
mod message;
mod round;
mod vertex;

pub use comm::{Comm, RawComm, CommError};
pub use message::{Message, TimeoutMessage, NoVoteMessage, Timeout, NoVote};
pub use message::{Action, Payload, Evidence};
pub use round::RoundNumber;
pub use vertex::Vertex;

use committable::{Committable, Commitment};
use serde::{Serialize, Deserialize};

/// The empty type has no values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Empty {}

impl Committable for Empty {
    fn commit(&self) -> Commitment<Self> {
        unreachable!("No value of `Empty` can be constructed.")
    }
}
