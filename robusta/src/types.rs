use std::{
    borrow::Cow,
    fmt,
    ops::{Add, AddAssign, Deref},
};

use bon::Builder;
use data_encoding::BASE64URL_NOPAD;
use espresso_types::{NsProof, Transaction};
use hotshot_query_service::VidCommon;
use minicbor::{Decode, Encode};
use multisig::{Unchecked, Validated};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use timeboost_types::CertifiedBlock;

#[derive(Debug, Deserialize, Serialize, Builder)]
pub(crate) struct TransactionsWithProof {
    pub(crate) transactions: Vec<Transaction>,
    pub(crate) proof: Option<NsProof>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VidCommonResponse {
    pub(crate) common: VidCommon,
}

#[derive(Debug, Decode)]
#[cbor(map)]
pub(crate) struct RecvBody {
    #[cbor(n(0))]
    pub(crate) blocks: Vec<CertifiedBlock<Unchecked>>,
}

#[derive(Debug, Encode)]
#[cbor(map)]
pub(crate) struct SendBody<'a> {
    #[cbor(n(0))]
    pub(crate) blocks: &'a [CertifiedBlock<Validated>],
}

macro_rules! Primitive {
    ($name:ident, $t:ty) => {
        #[derive(
            Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name($t);

        impl From<$t> for $name {
            fn from(val: $t) -> Self {
                Self(val)
            }
        }

        impl From<$name> for $t {
            fn from(val: $name) -> Self {
                val.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl Deref for $name {
            type Target = $t;

            fn deref(&self) -> &$t {
                &self.0
            }
        }

        impl Add for $name {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0 + rhs.0)
            }
        }

        impl Add<$t> for $name {
            type Output = Self;

            fn add(self, rhs: $t) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs
            }
        }

        impl AddAssign<$t> for $name {
            fn add_assign(&mut self, rhs: $t) {
                *self = *self + rhs
            }
        }
    };
}

Primitive!(Height, u64);

// Known base64 tags:
pub(crate) const TX: usize = 0;
pub(crate) const BLOCK: usize = 1;

#[derive(Debug, Clone)]
pub(crate) struct TaggedBase64<const T: usize>(Vec<u8>);

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
