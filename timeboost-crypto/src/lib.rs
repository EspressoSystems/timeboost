pub mod cp_proof;
pub mod sg_encryption;
pub mod traits;

pub type G = ark_secp256k1::Projective;
pub type H = Sha256;
pub type D = DigestBridge<H>;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nimue::DigestBridge;
use sha2::Sha256;

pub struct SerdeAs;

impl<T> serde_with::SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serde_with::Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        T::deserialize_compressed(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}
