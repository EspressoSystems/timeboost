use crate::types::round_number::RoundNumber;
use committable::Committable;
use serde::{Deserialize, Serialize};

use super::time::Timestamp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct BlockHeader {
    round: RoundNumber,
    timestamp: Timestamp,
}

impl BlockHeader {
    pub fn new(round: RoundNumber, timestamp: Timestamp) -> Self {
        Self { round, timestamp }
    }

    pub fn size_bytes(&self) -> usize {
        self.round.size_bytes() + self.timestamp.size_bytes()
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl Committable for BlockHeader {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("BlockHeader")
            .field("round", self.round.commit())
            .u64_field("timestamp", *self.timestamp)
            .finalize()
    }
}
