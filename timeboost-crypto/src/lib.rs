pub mod cp_proof;
pub mod feldman;
mod interpolation;
pub mod mre;
pub mod prelude;
pub(crate) mod serde_bridge;
pub mod sg_encryption;
pub mod traits;
pub mod vess;

use ark_ec::CurveGroup;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ff::field_hashers::DefaultFieldHasher;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use cp_proof::Proof;
use derive_more::From;
use digest::{generic_array::GenericArray, typenum};
use multisig::Committee;
use serde::{Deserialize, Serialize};
use serde_bridge::SerdeAs;
use serde_with::serde_as;
use sg_encryption::ShoupGennaro;
use sha2::Sha256;
use spongefish::DigestBridge;
use std::fmt;
use std::{convert::TryFrom, num::NonZeroUsize};
use traits::threshold_enc::ThresholdEncScheme;
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO(alex): we should relocate these types to sg_encryption?
#[derive(Copy, Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce(u128);

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct KeysetId(u64);

impl fmt::Display for KeysetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeysetId({})", self.0)
    }
}

impl TryFrom<&[u8]> for KeysetId {
    type Error = InvalidKeysetId;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 8] = value
            .get(..8)
            .ok_or(InvalidKeysetId(()))?
            .try_into()
            .map_err(|_| InvalidKeysetId(()))?;
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

impl Committable for KeysetId {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("KeysetId");
        builder.u64(self.0).finalize()
    }
}

#[derive(Clone, Copy, Debug)]
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
    pub fn id(&self) -> KeysetId {
        self.id
    }

    pub fn size(&self) -> NonZeroUsize {
        self.size
    }

    /// threshold where at least one is honest (=f+1) where f is faulty (inclusive) upperbound
    pub fn one_honest_threshold(&self) -> NonZeroUsize {
        let t = self.size().get().div_ceil(3);
        NonZeroUsize::new(t).expect("ceil(n/3) with n > 0 never gives 0")
    }

    /// threshold where the majority of honest nodes will agree (>=2f+1)
    pub fn honest_majority_threshold(&self) -> NonZeroUsize {
        let t = self.size().get() * 2 / 3 + 1;
        NonZeroUsize::new(t).expect("ceil(2n/3) with n > 0 never gives 0")
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Hash)]
pub struct CombKey<C: CurveGroup> {
    #[serde_as(as = "Vec<SerdeAs>")]
    pub key: Vec<C>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Hash)]
pub struct PublicKey<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    key: C,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, From)]
pub struct KeyShare<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    share: C::ScalarField,
    index: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext(Vec<u8>);

#[serde_as]
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    v: C,
    #[serde_as(as = "SerdeAs")]
    w_hat: C,
    e: Vec<u8>,
    nonce: Nonce,
    pi: Proof,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DecShare<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
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
    pub fn get_pub_share(&self, idx: usize) -> Option<&C> {
        self.key.get(idx)
    }
}

impl<C: CurveGroup> KeyShare<C> {
    pub fn share(&self) -> &C::ScalarField {
        &self.share
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

impl<C: CurveGroup> DecShare<C> {
    pub fn index(&self) -> u32 {
        self.index
    }
}

// Type initialization for decryption scheme
type G = ark_bls12_381::G1Projective;
type H = Sha256;
type D = DigestBridge<H>;
type H2C = MapToCurveBasedHasher<G, DefaultFieldHasher<H>, WBMap<ark_bls12_381::g1::Config>>;

pub struct DecryptionScheme(ShoupGennaro<G, H, D, H2C>);

pub type TrustedKeyMaterial = (
    <DecryptionScheme as ThresholdEncScheme>::PublicKey,
    <DecryptionScheme as ThresholdEncScheme>::CombKey,
    Vec<<DecryptionScheme as ThresholdEncScheme>::KeyShare>,
);

impl DecryptionScheme {
    /// Trusted Keygen Outputs:
    /// - A single public key for clients to encrypt their transaction bundles.
    /// - A single combination key to all nodes for combining partially decrypted ciphertexts.
    /// - One distinct private key share per node for partial decryption.
    pub fn trusted_keygen(committee: Committee) -> TrustedKeyMaterial {
        let mut rng = ark_std::rand::thread_rng();
        <DecryptionScheme as ThresholdEncScheme>::keygen(&mut rng, &committee).unwrap()
    }

    /// Same as [`trusted_keygen`], except accepting a caller-provided RNG
    pub fn trusted_keygen_with_rng<R: ark_std::rand::Rng>(
        committee: Committee,
        rng: &mut R,
    ) -> TrustedKeyMaterial {
        <DecryptionScheme as ThresholdEncScheme>::keygen(rng, &committee).unwrap()
    }
}

impl ThresholdEncScheme for DecryptionScheme {
    type PublicKey = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::PublicKey;
    type Committee = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::Committee;
    type CombKey = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::CombKey;
    type KeyShare = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::KeyShare;
    type Plaintext = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::Plaintext;
    type AssociatedData = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::AssociatedData;
    type Ciphertext = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::Ciphertext;
    type DecShare = <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::DecShare;

    fn keygen<R: ark_std::rand::Rng>(
        rng: &mut R,
        committee: &Committee,
    ) -> Result<
        (Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>),
        traits::threshold_enc::ThresholdEncError,
    > {
        <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::keygen(rng, committee)
    }

    fn encrypt<R: ark_std::rand::Rng>(
        rng: &mut R,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Ciphertext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::encrypt(rng, pk, message, aad)
    }

    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::DecShare, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::decrypt(sk, ciphertext, aad)
    }

    fn combine(
        committee: &Committee,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Plaintext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D, H2C> as ThresholdEncScheme>::combine(
            committee, comb_key, dec_shares, ciphertext, aad,
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid keyset id")]
pub struct InvalidKeysetId(());
