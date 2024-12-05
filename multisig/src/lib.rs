mod cert;
mod committee;
mod envelope;
mod util;
mod votes;

use std::cmp::Ordering;
use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use data_encoding::BASE64URL_NOPAD;
use ed25519_compact as ed25519;
use serde::{Deserialize, Serialize};

pub use cert::Certificate;
pub use committee::Committee;
pub use envelope::{Envelope, Unchecked, Validated};
pub use votes::VoteAccumulator;

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
        Self {
            pair: ed25519::KeyPair::generate(),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            pair: ed25519::KeyPair::from_seed(ed25519::Seed::new(seed)),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey { key: self.pair.pk }
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey {
            key: self.pair.sk.clone(),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        Signature {
            sig: self.pair.sk.sign(data, Some(ed25519::Noise::generate())),
        }
    }

    pub fn sign_deterministically(&self, data: &[u8]) -> Signature {
        Signature {
            sig: self.pair.sk.sign(data, None),
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
    pub fn sign(&self, data: &[u8]) -> Signature {
        Signature {
            sig: self.key.sign(data, Some(ed25519::Noise::generate())),
        }
    }

    pub fn sign_deterministically(&self, data: &[u8]) -> Signature {
        Signature {
            sig: self.key.sign(data, None),
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

impl From<[u8; 32]> for PublicKey {
    fn from(value: [u8; 32]) -> Self {
        PublicKey {
            key: ed25519::PublicKey::new(value),
        }
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = ed25519::SecretKey::from_slice(value).map_err(|_| InvalidSecretKey(()))?;
        Ok(Self { key: k })
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = ed25519::PublicKey::from_slice(value).map_err(|_| InvalidPublicKey(()))?;
        Ok(Self { key: k })
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
        write!(f, "{}", BASE64URL_NOPAD.encode(&self.as_bytes()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64URL_NOPAD.encode(&self.as_bytes()))
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
#[error("invalid secret key")]
pub struct InvalidSecretKey(());

#[derive(Debug, thiserror::Error)]
#[error("invalid public key")]
pub struct InvalidPublicKey(());

#[derive(Debug, thiserror::Error)]
#[error("invalid signature")]
pub struct InvalidSignature(());

#[cfg(feature = "tagged-base64")]
impl TryFrom<&tagged_base64::TaggedBase64> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(value: &tagged_base64::TaggedBase64) -> Result<Self, Self::Error> {
        Self::try_from(&value.value()[..])
    }
}

#[cfg(feature = "tagged-base64")]
impl TryFrom<&tagged_base64::TaggedBase64> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: &tagged_base64::TaggedBase64) -> Result<Self, Self::Error> {
        Self::try_from(&value.value()[..])
    }
}

#[cfg(feature = "tagged-base64")]
impl TryFrom<&tagged_base64::TaggedBase64> for Signature {
    type Error = InvalidSignature;

    fn try_from(value: &tagged_base64::TaggedBase64) -> Result<Self, Self::Error> {
        Self::try_from(&value.value()[..])
    }
}

#[cfg(feature = "tagged-base64")]
impl From<&SecretKey> for tagged_base64::TaggedBase64 {
    fn from(value: &SecretKey) -> Self {
        Self::new("SecretKey", value.as_slice()).expect("valid tag")
    }
}

#[cfg(feature = "tagged-base64")]
impl From<PublicKey> for tagged_base64::TaggedBase64 {
    fn from(value: PublicKey) -> Self {
        Self::new("PublicKey", value.as_slice()).expect("valid tag")
    }
}

#[cfg(feature = "tagged-base64")]
impl From<Signature> for tagged_base64::TaggedBase64 {
    fn from(value: Signature) -> Self {
        Self::new("Signature", value.as_slice()).expect("valid tag")
    }
}
