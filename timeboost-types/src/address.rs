use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address([u8; 32]);

impl Address {
    pub fn zero() -> Self {
        Self([0; 32])
    }
}

impl Committable for Address {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Address")
            .fixed_size_bytes(&self.0)
            .finalize()
    }
}
