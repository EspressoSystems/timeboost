pub mod cp_proof;
pub mod sg_encryption;
pub mod traits;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cp_proof::Proof;
use digest::{generic_array::GenericArray, typenum};
use nimue::DigestBridge;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sg_encryption::ShoupGennaro;
use sha2::Sha256;
use std::{convert::TryFrom, num::NonZeroUsize};
use traits::threshold_enc::ThresholdEncScheme;

#[derive(Copy, Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce(u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeysetId(u64);

impl TryFrom<&[u8]> for KeysetId {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 8] = value.try_into()?;
        Ok(KeysetId(u64::from_be_bytes(bytes)))
    }
}

impl From<u64> for KeysetId {
    fn from(value: u64) -> Self {
        KeysetId(value)
    }
}

impl From<KeysetId> for u64 {
    fn from(val: KeysetId) -> Self {
        val.0
    }
}

#[derive(Clone)]
pub struct Keyset {
    id: KeysetId,
    size: NonZeroUsize,
}

impl Keyset {
    pub fn new(id: u64, size: NonZeroUsize) -> Self {
        Keyset {
            id: KeysetId::from(id),
            size,
        }
    }
}

impl Keyset {
    pub fn size(&self) -> NonZeroUsize {
        self.size
    }

    pub fn threshold(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.size.get() / 3).expect("ceil(n/3) with n > 0 never gives 0")
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CombKey<C: CurveGroup> {
    #[serde_as(as = "Vec<crate::SerdeAs>")]
    pub key: Vec<C>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    key: C,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyShare<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    share: C::ScalarField,
    index: u32,
}

#[derive(Debug, Clone)]
pub struct Plaintext(Vec<u8>);

#[serde_as]
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    v: C,
    #[serde_as(as = "crate::SerdeAs")]
    w_hat: C,
    e: Vec<u8>,
    nonce: Nonce,
    pi: Proof,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecShare<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    w: C,
    index: u32,
    phi: Proof,
}

impl Nonce {
    pub fn new(value: u128) -> Self {
        Nonce(value)
    }

    pub fn as_bytes(&self) -> [u8; 16] {
        self.0.to_le_bytes()
    }
}

impl From<GenericArray<u8, typenum::U12>> for Nonce {
    fn from(array: GenericArray<u8, typenum::U12>) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..12].copy_from_slice(array.as_slice());
        Nonce(u128::from_le_bytes(bytes))
    }
}

impl From<Nonce> for GenericArray<u8, typenum::U12> {
    fn from(val: Nonce) -> Self {
        GenericArray::clone_from_slice(&val.as_bytes()[..12])
    }
}

impl<C: CurveGroup> CombKey<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("serializing combkey")
    }
}

impl<C: CurveGroup> TryFrom<&str> for CombKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v = bs58::decode(value)
            .into_vec()
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        let b = v.as_slice();
        Self::try_from(b)
    }
}

impl<C: CurveGroup> TryFrom<&[u8]> for CombKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(val, _)| val)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

impl<C: CurveGroup> PublicKey<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("serializing public key")
    }
}

impl<C: CurveGroup> TryFrom<&str> for PublicKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v = bs58::decode(value)
            .into_vec()
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        let b = v.as_slice();
        Self::try_from(b)
    }
}

impl<C: CurveGroup> TryFrom<&[u8]> for PublicKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(val, _)| val)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

impl<C: CurveGroup> KeyShare<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("serializing key share")
    }
}

impl<C: CurveGroup> TryFrom<&str> for KeyShare<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let v = bs58::decode(value)
            .into_vec()
            .map_err(|_| ark_serialize::SerializationError::InvalidData)?;
        let b = v.as_slice();
        Self::try_from(b)
    }
}

impl<C: CurveGroup> TryFrom<&[u8]> for KeyShare<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(value, bincode::config::standard())
            .map(|(val, _)| val)
            .map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

impl Plaintext {
    pub fn new(data: Vec<u8>) -> Self {
        Plaintext(data)
    }
}

impl From<Plaintext> for Vec<u8> {
    fn from(plaintext: Plaintext) -> Self {
        plaintext.0
    }
}

impl<C: CurveGroup> Ciphertext<C> {
    pub fn nonce(&self) -> Nonce {
        self.nonce
    }
}

// Type initialization for decryption scheme
type G = ark_secp256k1::Projective;
type H = Sha256;
type D = DigestBridge<H>;

pub struct DecryptionScheme(ShoupGennaro<G, H, D>);

type TrustedKeyMaterial = (
    <DecryptionScheme as ThresholdEncScheme>::PublicKey,
    <DecryptionScheme as ThresholdEncScheme>::CombKey,
    Vec<<DecryptionScheme as ThresholdEncScheme>::KeyShare>,
);
impl DecryptionScheme {
    /// Trusted Keygen Outputs:
    /// - A single public key for clients to encrypt their transaction bundles.
    /// - A single combination key to all nodes for combining partially decrypted ciphertexts.
    /// - One distinct private key share per node for partial decryption.
    pub fn trusted_keygen(size: NonZeroUsize) -> TrustedKeyMaterial {
        // TODO: fix committee id when dynamic keysets
        let mut rng = ark_std::rand::thread_rng();
        let keyset = Keyset::new(1, size);
        <DecryptionScheme as ThresholdEncScheme>::keygen(&mut rng, &keyset).unwrap()
    }
}

impl ThresholdEncScheme for DecryptionScheme {
    type PublicKey = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::PublicKey;
    type Committee = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Committee;
    type CombKey = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::CombKey;
    type KeyShare = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::KeyShare;
    type Plaintext = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Plaintext;
    type Ciphertext = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Ciphertext;
    type DecShare = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::DecShare;

    fn keygen<R: ark_std::rand::Rng>(
        rng: &mut R,
        committee: &Keyset,
    ) -> Result<
        (Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>),
        traits::threshold_enc::ThresholdEncError,
    > {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::keygen(rng, committee)
    }

    fn encrypt<R: ark_std::rand::Rng>(
        rng: &mut R,
        committee: &Keyset,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::encrypt(rng, committee, pk, message)
    }

    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::decrypt(sk, ciphertext)
    }

    fn combine(
        committee: &Keyset,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::combine(
            committee, comb_key, dec_shares, ciphertext,
        )
    }
}

pub struct SerdeAs;

impl<T> serde_with::SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serde_with::Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de, T> serde_with::DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        T::deserialize_compressed(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}
