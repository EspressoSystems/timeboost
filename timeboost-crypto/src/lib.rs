pub mod cp_proof;
pub mod sg_encryption;
pub mod traits;

use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cp_proof::{CPParameters, Proof};
use nimue::{DigestBridge, DuplexHash};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sg_encryption::ShoupGennaro;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use traits::threshold_enc::ThresholdEncScheme;
#[derive(Clone)]
pub struct Committee {
    pub id: u32,
    pub size: u32,
}

pub struct Parameters<C: CurveGroup, H: Digest, D: DuplexHash> {
    _hash: PhantomData<H>,
    pub committee: Committee,
    pub generator: C,
    pub cp_params: CPParameters<C, D>,
}
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CombKey<C: CurveGroup> {
    #[serde_as(as = "Vec<crate::SerdeAs>")]
    pub key: Vec<C>,
}

impl<C: CurveGroup> CombKey<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("serialization of combkey")
    }
}

impl<C: CurveGroup> TryFrom<&String> for CombKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
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
        bincode::deserialize(value).map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    key: C,
}

impl<C: CurveGroup> PublicKey<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("serialization of public key")
    }
}

impl<C: CurveGroup> TryFrom<&String> for PublicKey<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
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
        bincode::deserialize(value).map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyShare<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    share: C::ScalarField,
    index: u32,
}

impl<C: CurveGroup> KeyShare<C> {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).expect("serialization of key share")
    }
}

impl<C: CurveGroup> TryFrom<&String> for KeyShare<C> {
    type Error = ark_serialize::SerializationError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
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
        bincode::deserialize(value).map_err(|_| ark_serialize::SerializationError::InvalidData)
    }
}

#[derive(Debug)]
pub struct Plaintext(Vec<u8>);

impl Plaintext {
    pub fn new(data: Vec<u8>) -> Self {
        Plaintext(data)
    }
}

pub struct Ciphertext<C: CurveGroup> {
    v: C,
    w_hat: C,
    e: Vec<u8>,
    nonce: Vec<u8>,
    pi: Proof,
}

#[derive(Clone)]
pub struct DecShare<C: CurveGroup> {
    w: C,
    index: u32,
    phi: Proof,
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
    pub fn trusted_keygen(size: u32) -> TrustedKeyMaterial {
        // TODO: fix committee id when dynamic keysets
        let mut rng = ark_std::rand::thread_rng();
        let committee = Committee { id: 0, size };
        let parameters =
            <DecryptionScheme as ThresholdEncScheme>::setup(&mut rng, committee).unwrap();
        <DecryptionScheme as ThresholdEncScheme>::keygen(&mut rng, &parameters).unwrap()
    }
}

impl ThresholdEncScheme for DecryptionScheme {
    type PublicKey = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::PublicKey;
    type Committee = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Committee;
    type Parameters = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Parameters;
    type CombKey = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::CombKey;
    type KeyShare = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::KeyShare;
    type Plaintext = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Plaintext;
    type Ciphertext = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::Ciphertext;
    type DecShare = <ShoupGennaro<G, H, D> as ThresholdEncScheme>::DecShare;

    fn setup<R: ark_std::rand::Rng>(
        rng: &mut R,
        committee: Self::Committee,
    ) -> Result<Self::Parameters, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::setup(rng, committee)
    }

    fn keygen<R: ark_std::rand::Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<
        (Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>),
        traits::threshold_enc::ThresholdEncError,
    > {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::keygen(rng, pp)
    }

    fn encrypt<R: ark_std::rand::Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::encrypt(rng, pp, pk, message)
    }

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::decrypt(pp, sk, ciphertext)
    }

    fn combine(
        pp: &Self::Parameters,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, traits::threshold_enc::ThresholdEncError> {
        <ShoupGennaro<G, H, D> as ThresholdEncScheme>::combine(pp, comb_key, dec_shares, ciphertext)
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
