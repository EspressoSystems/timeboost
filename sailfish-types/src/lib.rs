mod comm;
mod message;
mod round;
mod vertex;

pub use comm::{Comm, CommError, RawComm};
pub use message::{Action, Evidence, Payload};
pub use message::{Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage};
pub use round::RoundNumber;
pub use vertex::Vertex;

use committable::{Commitment, Committable};
use serde::{Deserialize, Serialize};

/// The empty type has no values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Empty {}

impl Committable for Empty {
    fn commit(&self) -> Commitment<Self> {
        unreachable!("No value of `Empty` can be constructed.")
    }
}
