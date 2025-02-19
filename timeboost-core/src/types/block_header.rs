use committable::Committable;
use serde::{Deserialize, Serialize};

use super::time::Timestamp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct BlockHeader<R> {
    round: R,
    timestamp: Timestamp,
}

impl<R> BlockHeader<R> {
    pub fn new(round: R, timestamp: Timestamp) -> Self {
        Self { round, timestamp }
    }

    pub fn round(&self) -> &R {
        &self.round
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl<R: Committable> Committable for BlockHeader<R> {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("BlockHeader")
            .field("round", self.round.commit())
            .u64_field("timestamp", *self.timestamp)
            .finalize()
    }
}
