use std::{borrow::Cow, fmt};

use bon::Builder;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// An Espresso transaction.
///
/// https://docs.espressosys.com/network/api-reference/sequencer-api#transaction
#[derive(Debug, Serialize, Builder)]
pub struct Transaction<'a> {
    pub(crate) namespace: u32,
    #[serde(with = "serde_bytes")]
    pub(crate) payload: &'a [u8],
}

/// An Expresso transaction hash.
///
/// https://docs.espressosys.com/network/api-reference/sequencer-api#tagged-base-64
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TxHash(TaggedBase64<TX>);

/// An Expresso block hash.
///
/// https://docs.espressosys.com/network/api-reference/sequencer-api#tagged-base-64
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlockHash(TaggedBase64<BLOCK>);

/// Espresso transaction information.
///
/// https://docs.espressosys.com/network/api-reference/sequencer-api/availability-api#returns-1
#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct TxInfo<T> {
    pub(crate) hash: TxHash,
    pub(crate) block_hash: BlockHash,
    pub(crate) block_height: u64,
    pub(crate) index: u64,
    pub(crate) proof: T,
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Known base64 tags:
const TX: usize = 0;
const BLOCK: usize = 1;

#[derive(Debug, Clone)]
struct TaggedBase64<const T: usize>(Vec<u8>);

impl<const T: usize> Serialize for TaggedBase64<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        const { assert!(T == TX || T == BLOCK) }

        let mut val = String::new();

        match T {
            TX => val.push_str("TX~"),
            BLOCK => val.push_str("BLOCK~"),
            _ => unreachable!(),
        }

        BASE64URL_NOPAD.encode_append(&self.0, &mut val);
        val.serialize(s)
    }
}

impl<'de, const T: usize> Deserialize<'de> for TaggedBase64<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        const { assert!(T == TX || T == BLOCK) }

        let val = <Cow<'de, str>>::deserialize(d)?;

        let val = match T {
            TX => split("TX", &val)?,
            BLOCK => split("BLOCK", &val)?,
            _ => unreachable!(),
        };

        let vec = BASE64URL_NOPAD
            .decode(val.as_bytes())
            .map_err(de::Error::custom)?;

        Ok(Self(vec))
    }
}

fn split<'a, E: de::Error>(expected: &str, val: &'a str) -> Result<&'a str, E> {
    match val.split_once('~') {
        Some((tag, val)) => {
            if tag == expected {
                Ok(val)
            } else {
                Err(de::Error::custom(format!("invalid tag: {tag}")))
            }
        }
        None => Err(de::Error::custom("missing '~' delimiter")),
    }
}

impl<const T: usize> fmt::Display for TaggedBase64<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.serialize(f)
    }
}
