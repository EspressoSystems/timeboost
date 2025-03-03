use std::ops::Deref;

#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(bytes::Bytes);

impl From<bytes::Bytes> for Bytes {
    fn from(value: bytes::Bytes) -> Self {
        Self(value)
    }
}

impl From<Bytes> for bytes::Bytes {
    fn from(value: Bytes) -> Self {
        value.0
    }
}

impl Deref for Bytes {
    type Target = bytes::Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ssz::Decode for Bytes {
    fn is_ssz_fixed_len() -> bool {
        alloy_primitives::Bytes::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        alloy_primitives::Bytes::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let b = alloy_primitives::Bytes::from_ssz_bytes(bytes)?;
        Ok(Self(b.into()))
    }
}
