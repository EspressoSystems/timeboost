use std::ops::Deref;

use ed25519_compact as ed25519;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_bytes::ByteArray;

pub(crate) fn encode<S, T, const N: usize>(d: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Deref<Target = [u8; N]>,
{
    ByteArray::new(**d).serialize(s)
}

pub(crate) fn decode_pk<'de, D>(d: D) -> Result<ed25519::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let a = ByteArray::deserialize(d)?.into_array();
    if super::SMALL_ORDER_KEYS.contains(&&a) {
        return Err(de::Error::custom("small order public key detected"));
    }
    Ok(ed25519::PublicKey::new(a))
}

pub(crate) fn decode_sk<'de, D>(d: D) -> Result<ed25519::SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    let a = ByteArray::deserialize(d)?;
    Ok(ed25519::SecretKey::new(a.into_array()))
}

pub(crate) fn decode_sig<'de, D>(d: D) -> Result<ed25519::Signature, D::Error>
where
    D: Deserializer<'de>,
{
    let a = ByteArray::deserialize(d)?;
    Ok(ed25519::Signature::new(a.into_array()))
}
