use std::ops::Deref;

use ed25519_compact::x25519;
use minicbor::decode::{Decode, Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_bytes::ByteArray;

use crate::InvalidSecretKey;

pub(crate) fn serialize<S, T, const N: usize>(d: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Deref<Target = [u8; N]>,
{
    if s.is_human_readable() {
        bs58::encode(**d).into_string().serialize(s)
    } else {
        ByteArray::new(**d).serialize(s)
    }
}

pub(crate) fn deserialize_x25519_pk<'de, D>(d: D) -> Result<x25519::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        let mut a = [0; 32];
        let n = bs58::decode(&s).onto(&mut a).map_err(de::Error::custom)?;
        x25519::PublicKey::from_slice(&a[..n]).map_err(de::Error::custom)
    } else {
        let a = ByteArray::<32>::deserialize(d)?;
        x25519::PublicKey::from_slice(&a[..]).map_err(de::Error::custom)
    }
}

pub(crate) fn deserialize_x25519_sk<'de, D>(d: D) -> Result<x25519::SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        let mut a = [0; 32];
        let n = bs58::decode(&s).onto(&mut a).map_err(de::Error::custom)?;
        x25519::SecretKey::from_slice(&a[..n]).map_err(de::Error::custom)
    } else {
        let a = ByteArray::<32>::deserialize(d)?;
        x25519::SecretKey::from_slice(&a[..]).map_err(de::Error::custom)
    }
}

pub(crate) fn serialize_secp256k1_sk<S>(k: &secp256k1::SecretKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if s.is_human_readable() {
        bs58::encode(k.secret_bytes()).into_string().serialize(s)
    } else {
        ByteArray::new(k.secret_bytes()).serialize(s)
    }
}

pub(crate) fn deserialize_secp256k1_sk<'de, D>(d: D) -> Result<secp256k1::SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        let mut a = [0; 32];
        let n = bs58::decode(&s).onto(&mut a).map_err(de::Error::custom)?;
        if n != 32 {
            return Err(de::Error::custom(InvalidSecretKey(())));
        }
        secp256k1::SecretKey::from_byte_array(a).map_err(de::Error::custom)
    } else {
        let a = ByteArray::<32>::deserialize(d)?;
        secp256k1::SecretKey::from_byte_array(a.into_array()).map_err(de::Error::custom)
    }
}

pub(crate) fn serialize_secp256k1_pk<S>(k: &secp256k1::PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if s.is_human_readable() {
        bs58::encode(k.serialize()).into_string().serialize(s)
    } else {
        ByteArray::new(k.serialize()).serialize(s)
    }
}

pub(crate) fn deserialize_secp256k1_pk<'de, D>(d: D) -> Result<secp256k1::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        let mut a = [0; 33];
        let n = bs58::decode(&s).onto(&mut a).map_err(de::Error::custom)?;
        if n != 33 {
            return Err(de::Error::custom(InvalidSecretKey(())));
        }
        secp256k1::PublicKey::from_byte_array_compressed(a).map_err(de::Error::custom)
    } else {
        let a = ByteArray::<33>::deserialize(d)?;
        secp256k1::PublicKey::from_byte_array_compressed(a.into_array()).map_err(de::Error::custom)
    }
}

pub fn encode_secp256k1_sig<C, W>(
    s: &secp256k1::ecdsa::Signature,
    e: &mut Encoder<W>,
    _: &mut C,
) -> Result<(), EncodeError<W::Error>>
where
    W: Write,
{
    let a: [u8; 64] = s.serialize_compact();
    e.bytes(&a)?;
    Ok(())
}

pub fn decode_secp256k1_sig<'b, C>(
    d: &mut Decoder<'b>,
    _: &mut C,
) -> Result<secp256k1::ecdsa::Signature, DecodeError> {
    let p = d.position();
    let s = d.bytes()?;
    secp256k1::ecdsa::Signature::from_compact(s).map_err(|e| DecodeError::custom(e).at(p))
}

pub fn encode_secp256k1_pk<C, W>(
    k: &secp256k1::PublicKey,
    e: &mut Encoder<W>,
    _: &mut C,
) -> Result<(), EncodeError<W::Error>>
where
    W: Write,
{
    let a: [u8; 33] = k.serialize();
    e.bytes(&a)?;
    Ok(())
}

pub fn decode_secp256k1_pk<'b, C>(
    d: &mut Decoder<'b>,
    c: &mut C,
) -> Result<secp256k1::PublicKey, DecodeError> {
    let p = d.position();
    let a: [u8; 33] = minicbor::bytes::ByteArray::<33>::decode(d, c)?.into();
    secp256k1::PublicKey::from_byte_array_compressed(a).map_err(|e| DecodeError::custom(e).at(p))
}
