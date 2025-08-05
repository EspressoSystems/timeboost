use std::ops::{Deref, DerefMut};

use alloy::rlp::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    RlpDecodable,
    RlpEncodable,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[rlp(transparent)]
pub struct Bytes(alloy::primitives::Bytes);

impl From<bytes::Bytes> for Bytes {
    fn from(value: bytes::Bytes) -> Self {
        Self(alloy::primitives::Bytes(value))
    }
}

impl From<Bytes> for bytes::Bytes {
    fn from(value: Bytes) -> Self {
        value.0.into()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self::from(bytes::Bytes::from(value))
    }
}

impl Deref for Bytes {
    type Target = bytes::Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ssz::Decode for Bytes {
    fn is_ssz_fixed_len() -> bool {
        alloy::primitives::Bytes::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        alloy::primitives::Bytes::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let b = alloy::primitives::Bytes::from_ssz_bytes(bytes)?;
        Ok(Self(b))
    }
}
