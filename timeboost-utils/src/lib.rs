pub mod keyset;
pub mod load_generation;
pub mod types;
pub mod until;

use std::{borrow::Cow, fmt, ops::Deref, str::FromStr};

use crate::keyset::NodeConfig;
use multisig::x25519;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, value::StrDeserializer},
    ser::Error,
};

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    sig_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn unsafe_zero_dh_keypair<N: Into<u64>>(i: N) -> x25519::Keypair {
    dh_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn sig_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(new_seed)
}

pub fn dh_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> x25519::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    x25519::Keypair::from_seed(new_seed).unwrap()
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

/// Selects peer hosts from a keyset according to region logic.
/// The selection is based on the offset of the file. The file is
/// arranged with 20 keys, and each group of 4 is associated with
/// a region. If `multi_region` is true, the selection will be
/// based on the region, where it'll offset. So if we have 5 nodes
/// then the indexing scheme would be 0 5 10 15 for the region.
///
/// - `keyset` is the slice of PublicNodeInfo (from KeysetConfig)
/// - `nodes` is the number of nodes to select
/// - `multi_region` determines whether to use region chunking logic
///
/// Returns a boxed iterator over the selected PublicNodeInfo references.
pub fn select_peer_hosts(
    keyset: &[NodeConfig],
    multi_region: bool,
) -> impl Iterator<Item = &NodeConfig> {
    if multi_region {
        let take_from_group = keyset.len() / 4;
        Box::new(
            keyset
                .chunks(4)
                .flat_map(move |v| v.iter().take(take_from_group)),
        )
    } else {
        Box::new(keyset.iter().take(keyset.len())) as Box<dyn Iterator<Item = _>>
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bs58Bincode<T>(T);

impl<T> Bs58Bincode<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Bs58Bincode<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: DeserializeOwned> Bs58Bincode<T> {
    pub fn try_from_bytes(value: &[u8]) -> Result<Self, serde::de::value::Error> {
        let s = std::str::from_utf8(value).map_err(serde::de::value::Error::custom)?;
        s.parse()
    }
}

impl<T> From<T> for Bs58Bincode<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: DeserializeOwned> FromStr for Bs58Bincode<T> {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::deserialize(StrDeserializer::new(s))
    }
}

impl<T: Serialize> Serialize for Bs58Bincode<T> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = bincode::serde::encode_to_vec(&self.0, bincode::config::standard())
            .map_err(serde::ser::Error::custom)?;
        bs58::encode(bytes).into_string().serialize(s)
    }
}

impl<T: Serialize> fmt::Display for Bs58Bincode<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Bs58Bincode<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = <Cow<'de, str>>::deserialize(d)?;
        let bytes = bs58::decode(&*str)
            .into_vec()
            .map_err(serde::de::Error::custom)?;
        let (val, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard().with_limit::<8192>(),
        )
        .map_err(serde::de::Error::custom)?;
        Ok(Self(val))
    }
}
