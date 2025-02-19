use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use sailfish_types::{Message, RoundNumber};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(RoundNumber, [u8; 32]);

impl Digest {
    pub fn new<B: Committable, S>(d: &Message<B, S>) -> Self {
        Self(d.round(), d.commit().into())
    }

    pub fn round(&self) -> RoundNumber {
        self.0
    }
}

impl Committable for Digest {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("RBC Message Digest")
            .field("round", self.0.commit())
            .fixed_size_field("digest", &self.1)
            .finalize()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({},{})",
            self.0,
            bs58::encode(&self.1[..]).into_string()
        )
    }
}
