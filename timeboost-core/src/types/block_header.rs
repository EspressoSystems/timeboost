use committable::Committable;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BlockHeader {}
impl BlockHeader {
    pub fn size_bytes(&self) -> usize {
        0
    }
}

impl Committable for BlockHeader {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("BlockHeader").finalize()
    }
}
