use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use timeboost_core::types::message::Message;
use timeboost_utils::types::round_number::RoundNumber;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Digest(RoundNumber, [u8; 32]);

impl Digest {
    pub fn new<S>(d: &Message<S>) -> Self {
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
        write!(f, "({},{})", self.0, BASE64URL_NOPAD.encode(&self.1[..]))
    }
}
