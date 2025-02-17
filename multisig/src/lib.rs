mod cert;
mod committee;
mod envelope;
mod signed;
mod util;
mod votes;

pub mod x25519;

use std::cmp::Ordering;
use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use ed25519_compact as ed25519;
use serde::{Deserialize, Serialize};

pub use cert::Certificate;
pub use committee::Committee;
pub use envelope::{Envelope, Unchecked, Validated};
pub use signed::Signed;
pub use votes::VoteAccumulator;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(u8);

impl KeyId {
    pub fn to_bytes(self) -> [u8; 1] {
        [self.0]
    }
}

impl From<u8> for KeyId {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

impl From<KeyId> for usize {
    fn from(val: KeyId) -> Self {
        val.0.into()
    }
}

impl From<KeyId> for u64 {
    fn from(val: KeyId) -> Self {
        val.0.into()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
    pair: ed25519::KeyPair,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey {
    #[serde(serialize_with = "util::encode", deserialize_with = "util::decode_pk")]
    key: ed25519::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey {
    #[serde(serialize_with = "util::encode", deserialize_with = "util::decode_sk")]
    key: ed25519::SecretKey,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature {
    #[serde(serialize_with = "util::encode", deserialize_with = "util::decode_sig")]
    sig: ed25519::Signature,
}

impl Keypair {
    pub fn generate() -> Self {
        let this = Self {
            pair: ed25519::KeyPair::generate(),
        };
        assert!(!SMALL_ORDER_KEYS.contains(&&*this.pair.pk));
        this
    }

    /// Generate keypair from a seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let this = Self {
            pair: ed25519::KeyPair::from_seed(ed25519::Seed::new(seed)),
        };
        assert!(!SMALL_ORDER_KEYS.contains(&&*this.pair.pk));
        this
    }

    pub fn from_private_key(priv_key: SecretKey) -> Self {
        let pair = ed25519::KeyPair {
            pk: priv_key.public_key().key,
            sk: priv_key.key,
        };
        Self { pair }
    }

    /// Returns ed25519 Public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey { key: self.pair.pk }
    }

    /// Return ed25519 secret key.
    pub fn secret_key(&self) -> SecretKey {
        SecretKey {
            key: self.pair.sk.clone(),
        }
    }

    /// Sign data with our ed25519 secret key.
    pub fn sign(&self, data: &[u8], deterministic: bool) -> Signature {
        Signature {
            sig: self
                .pair
                .sk
                .sign(data, (!deterministic).then(ed25519::Noise::generate)),
        }
    }
}

impl PublicKey {
    pub fn is_valid(&self, data: &[u8], s: &Signature) -> bool {
        self.key.verify(data, &s.sig).is_ok()
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        *self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

impl SecretKey {
    pub fn sign(&self, data: &[u8], deterministic: bool) -> Signature {
        Signature {
            sig: self
                .key
                .sign(data, (!deterministic).then(ed25519::Noise::generate)),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            key: self.key.public_key(),
        }
    }

    pub fn as_bytes(&self) -> [u8; 64] {
        *self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

impl Signature {
    pub fn as_bytes(&self) -> [u8; 64] {
        *self.sig
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.sig[..]
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = ed25519::SecretKey::from_slice(value).map_err(|_| InvalidSecretKey(()))?;
        Ok(Self { key: k })
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        bs58::decode(s)
            .into_vec()
            .map_err(|_| InvalidSecretKey(()))
            .and_then(|v| SecretKey::try_from(v.as_slice()))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = ed25519::PublicKey::from_slice(value).map_err(|_| InvalidPublicKey(()))?;
        if SMALL_ORDER_KEYS.contains(&&*k) {
            return Err(InvalidPublicKey(()));
        }
        Ok(Self { key: k })
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        bs58::decode(s)
            .into_vec()
            .map_err(|_| InvalidPublicKey(()))
            .and_then(|v| PublicKey::try_from(v.as_slice()))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = InvalidSignature;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let s = ed25519::Signature::from_slice(value).map_err(|_| InvalidSignature(()))?;
        Ok(Self { sig: s })
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key[..].cmp(&other.key[..])
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sig[..].cmp(&other.sig[..])
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey")
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &self.public_key())
            .field("secret_key", &"SecretKey")
            .finish()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.as_bytes()).into_string())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.as_bytes()).into_string())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl Committable for Signature {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Signature")
            .fixed_size_field("sig", &self.as_bytes())
            .finalize()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid keypair")]
pub struct InvalidKeypair(());

#[derive(Debug, thiserror::Error)]
#[error("invalid secret key")]
pub struct InvalidSecretKey(());

#[derive(Debug, thiserror::Error)]
#[error("invalid public key")]
pub struct InvalidPublicKey(());

#[derive(Debug, thiserror::Error)]
#[error("invalid signature")]
pub struct InvalidSignature(());

/// Taken from Table 6b of "Taming the many EdDSAs" (https://eprint.iacr.org/2020/1244.pdf)
///
/// These are small order public keys that may lead to repudiation attacks
/// and should be rejected.
const SMALL_ORDER_KEYS: [&[u8; 32]; 14] = [
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\xEC\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F",
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\xC7\x17\x6A\x70\x3D\x4D\xD8\x4F\xBA\x3C\x0B\x76\x0D\x10\x67\x0F\x2A\x20\x53\xFA\x2C\x39\xCC\xC6\x4E\xC7\xFD\x77\x92\xAC\x03\x7A",
    b"\xC7\x17\x6A\x70\x3D\x4D\xD8\x4F\xBA\x3C\x0B\x76\x0D\x10\x67\x0F\x2A\x20\x53\xFA\x2C\x39\xCC\xC6\x4E\xC7\xFD\x77\x92\xAC\x03\xFA",
    b"\x26\xE8\x95\x8F\xC2\xB2\x27\xB0\x45\xC3\xF4\x89\xF2\xEF\x98\xF0\xD5\xDF\xAC\x05\xD3\xC6\x33\x39\xB1\x38\x02\x88\x6D\x53\xFC\x05",
    b"\x26\xE8\x95\x8F\xC2\xB2\x27\xB0\x45\xC3\xF4\x89\xF2\xEF\x98\xF0\xD5\xDF\xAC\x05\xD3\xC6\x33\x39\xB1\x38\x02\x88\x6D\x53\xFC\x85",
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\xEC\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    b"\xEE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F",
    b"\xEE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    b"\xED\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    b"\xED\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F"
];
