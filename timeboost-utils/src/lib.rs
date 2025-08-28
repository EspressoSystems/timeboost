pub mod keyset;
pub mod load_generation;
pub mod types;
pub mod until;

use crate::keyset::NodeConfig;
use multisig::x25519;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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

/// Sometimes we don't want to reveal the struct inner fields when serializing.
/// This intermediate type holds the bs58::encode(bincode::encode(T)) string that treats
/// the type `T` as a `Serialize + Deserialize` blackbox.
///
/// # Rationale
///
/// A concrete motivating example is: if we serialize some config struct in toml format,
/// containing the public key `crypto::mre::EncryptionKey`, it will reveal the inner fields:
///
/// ```toml,no_run
/// [keys.dkg.pubilc]
/// u = "..."
///
/// # what we want:
/// [keys.dkg]
/// public = "..."
/// ```
///
/// One solution is to write customized serde function then use `serde(with="")` on the field
/// whose internals need to be masked in serialized output. This approach is ergonomic but slightly
/// error prone if that particular field's serialized value is taken out-of-context, and
/// the deserializer may forget to use the aforementioned custom deserializer.
///
/// Here we take another approach, being explicit about the expectation to use non-serde-default
/// `decode()` method to deserialize through the type system. The reason why we hold a String rather
/// than Bytes is the intended usage of this helper struct is human readable de/serializer where
/// the serialized values can have structured semantic. For bytes-orientated de/serializer,
/// revealing the internal structure is never a problem to begin with since they are just raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blackbox(String);

impl Blackbox {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// encode a value into a blackbox representation
    pub fn encode<T: Serialize>(v: T) -> anyhow::Result<Self> {
        let bytes = bincode::serde::encode_to_vec(v, bincode::config::standard())?;
        Ok(Self(bs58::encode(bytes).into_string()))
    }

    /// decode to the original value
    pub fn decode<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
        let bytes = bs58::decode(&self.0).into_vec()?;
        let (val, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard().with_limit::<8192>(),
        )?;
        Ok(val)
    }

    pub fn into_bytes(&self) -> Vec<u8> {
        self.0.clone().into_bytes()
    }

    pub fn from_bytes(v: Vec<u8>) -> anyhow::Result<Self> {
        let s = String::from_utf8(v)?;
        Ok(Self(s))
    }
}

#[test]
fn test_blackbox() {
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        id: u64,
        name: String,
        values: Vec<i32>,
        flag: bool,
    }

    let original = TestData {
        id: 42,
        name: "test_struct".to_string(),
        values: vec![1, 2, 3, 4, 5],
        flag: true,
    };

    let blackbox = Blackbox::encode(&original).expect("Failed to create blackbox");
    let decoded: TestData = blackbox.decode().expect("Failed to decode blackbox");
    assert_eq!(original, decoded);

    assert_eq!(
        Blackbox::from_bytes(blackbox.into_bytes()).unwrap(),
        blackbox
    );
}
