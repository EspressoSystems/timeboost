use committable::{Commitment, Committable};
use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TimeoutData {
    pub round: ViewNumber,
}

impl Committable for TimeoutData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("TimeoutData")
            .field("round", self.round.commit())
            .finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVoteData {
    pub round: ViewNumber,
}

impl Committable for NoVoteData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("NoVoteData")
            .field("round", self.round.commit())
            .finalize()
    }
}
