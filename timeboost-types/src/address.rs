use std::fmt;
use std::ops::Deref;

use alloy_rlp::{RlpDecodable, RlpEncodable};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    RlpEncodable,
    RlpDecodable,
    Serialize,
    Deserialize,
)]
pub struct Address([u8; 20]);

impl Address {
    pub fn zero() -> Self {
        Self([0; 20])
    }
}

impl From<[u8; 20]> for Address {
    fn from(value: [u8; 20]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Deref for Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Committable for Address {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Address")
            .fixed_size_bytes(&self.0)
            .finalize()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        HEXLOWER.encode_write(&self.0, f)
    }
}
