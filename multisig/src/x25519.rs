use std::cmp::Ordering;
use std::fmt;

use ed25519_compact::x25519;

use super::{InvalidKeypair, InvalidPublicKey, InvalidSecretKey};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
    pair: x25519::KeyPair,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    key: x25519::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretKey {
    key: x25519::SecretKey,
}

impl Keypair {
    pub fn public_key(&self) -> PublicKey {
        PublicKey { key: self.pair.pk }
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey {
            key: self.pair.sk.clone(),
        }
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

impl SecretKey {
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
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

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl TryFrom<crate::Keypair> for Keypair {
    type Error = InvalidKeypair;

    fn try_from(val: crate::Keypair) -> Result<Self, Self::Error> {
        Ok(Self {
            pair: x25519::KeyPair::from_ed25519(&val.pair).map_err(|_| InvalidKeypair(()))?,
        })
    }
}

impl TryFrom<crate::SecretKey> for SecretKey {
    type Error = InvalidSecretKey;

    fn try_from(val: crate::SecretKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key: x25519::SecretKey::from_ed25519(&val.key).map_err(|_| InvalidSecretKey(()))?,
        })
    }
}

impl TryFrom<crate::PublicKey> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(val: crate::PublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            key: x25519::PublicKey::from_ed25519(&val.key).map_err(|_| InvalidPublicKey(()))?,
        })
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = InvalidPublicKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let k = x25519::PublicKey::from_slice(value).map_err(|_| InvalidPublicKey(()))?;
        Ok(Self { key: k })
    }
}
