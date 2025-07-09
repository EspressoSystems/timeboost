mod comm;
mod committee;
mod message;
mod nodeinfo;
mod payload;
mod round;
mod time;
mod vertex;

pub mod math;

pub use comm::{Comm, CommError};
pub use committee::CommitteeVec;
pub use message::{Action, Evidence, Payload};
pub use message::{Handover, HandoverMessage};
pub use message::{Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage};
pub use nodeinfo::NodeInfo;
pub use payload::DataSource;
pub use round::{Round, RoundNumber};
pub use time::{ConsensusTime, HasTime, Timestamp};
pub use vertex::Vertex;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::CommitteeId;
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

pub const UNKNOWN_COMMITTEE_ID: CommitteeId = CommitteeId::new(u64::MAX);
