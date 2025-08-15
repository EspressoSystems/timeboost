mod cert;
mod committee;
mod envelope;
mod signed;
mod util;
mod votes;

pub mod x25519;

use std::fmt;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use secp256k1::rand::Rng;
use serde::{Deserialize, Serialize};

pub use cert::Certificate;
pub use committee::{Committee, CommitteeId};
pub use envelope::{Envelope, Unchecked, Validated};
pub use signed::Signed;
pub use votes::VoteAccumulator;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
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

impl From<KeyId> for u32 {
    fn from(val: KeyId) -> Self {
        val.0.into()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Keypair {
    sk: SecretKey,
    pk: PublicKey,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey {
    #[serde(serialize_with = "util::encode_secp256k1_pk")]
    #[serde(deserialize_with = "util::decode_secp256k1_pk")]
    key: secp256k1::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey {
    #[serde(serialize_with = "util::encode_secp256k1_sk")]
    #[serde(deserialize_with = "util::decode_secp256k1_sk")]
    key: secp256k1::SecretKey,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature {
    sig: secp256k1::ecdsa::Signature,
}

impl Keypair {
    pub fn generate() -> Self {
        let (sk, pk) = secp256k1::generate_keypair(&mut secp256k1::rand::rng());
        Self {
            sk: SecretKey { key: sk },
            pk: PublicKey { key: pk },
        }
    }

    pub fn generate_with_rng<R: Rng>(rng: &mut R) -> Self {
        let (sk, pk) = secp256k1::generate_keypair(rng);
        Self {
            sk: SecretKey { key: sk },
            pk: PublicKey { key: pk },
        }
    }

    /// Generate keypair from a seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        loop {
            if let Ok(sk) = secp256k1::SecretKey::from_byte_array(seed) {
                let pk = sk.public_key(secp256k1::SECP256K1);
                return Self {
                    sk: SecretKey { key: sk },
                    pk: PublicKey { key: pk },
                };
            }
        }
    }

    /// Returns ed25519 Public key.
    pub fn public_key(&self) -> PublicKey {
        self.pk
    }

    /// Return ed25519 secret key.
    pub fn secret_key(&self) -> SecretKey {
        self.sk.clone()
    }

    /// Sign data with our ed25519 secret key.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.sk.sign(data)
    }
}

impl PublicKey {
    pub fn is_valid(&self, data: &[u8], s: &Signature) -> bool {
        use secp256k1::hashes::{Hash, sha256};
        let hash = sha256::Hash::hash(data);
        let mesg = secp256k1::Message::from_digest(hash.to_byte_array());
        s.sig.verify(mesg, &self.key).is_ok()
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        self.key.serialize()
    }
}

impl SecretKey {
    pub fn sign(&self, data: &[u8]) -> Signature {
        use secp256k1::hashes::{Hash, sha256};
        let hash = sha256::Hash::hash(data);
        let mesg = secp256k1::Message::from_digest(hash.to_byte_array());
        Signature {
            sig: self.key.sign_ecdsa(mesg),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        let pk = self.key.public_key(secp256k1::SECP256K1);
        PublicKey { key: pk }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.key.secret_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.sig.serialize_compact()
    }
}

impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Self {
        let pk = sk.public_key();
        Self { sk, pk }
    }
}

impl TryFrom<[u8; 32]> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(value: [u8; 32]) -> Result<Self, Self::Error> {
        let k = secp256k1::SecretKey::from_byte_array(value).map_err(|_| InvalidSecretKey(()))?;
        Ok(Self { key: k })
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut a = [0; 32];
        let n = bs58::decode(s)
            .onto(&mut a)
            .map_err(|_| InvalidSecretKey(()))?;
        if n != 32 {
            return Err(InvalidSecretKey(()));
        }
        Self::try_from(a)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = secp256k1::PublicKey::from_slice(value).map_err(|_| InvalidPublicKey(()))?;
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
        let s =
            secp256k1::ecdsa::Signature::from_compact(value).map_err(|_| InvalidSignature(()))?;
        Ok(Self { sig: s })
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
        write!(f, "{}", bs58::encode(&self.to_bytes()).into_string())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(&self.to_bytes()).into_string())
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
            .fixed_size_field("sig", &self.to_bytes())
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
