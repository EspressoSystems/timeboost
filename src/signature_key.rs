use bitvec::{slice::BitSlice, vec::BitVec};
use digest::generic_array::GenericArray;
use ethereum_types::U256;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    hash::Hash,
};
use tagged_base64::TaggedBase64;

use crate::{qc::*, stake_table::StakeTableEntry};
use jf_signature::{
    bls_over_bn254::{BLSOverBN254CurveSignatureScheme, KeyPair, SignKey, VerKey},
    SignatureError, SignatureScheme,
};
use rand::SeedableRng;
use tracing::instrument;

/// BLS private key used to sign a message
pub type BLSPrivKey = SignKey;
/// BLS public key used to verify a signature
pub type BLSPubKey = VerKey;
/// Public parameters for BLS signature scheme
pub type BLSPublicParam = ();

/// Type representing stake table entries in a `StakeTable`
pub trait StakeTableEntryType<K> {
    /// Get the stake value
    fn stake(&self) -> U256;
    /// Get the public key
    fn public_key(&self) -> K;
}

/// Trait for abstracting public key signatures
/// Self is the public key type
pub trait SignatureKey:
    Send
    + Sync
    + Clone
    + Sized
    + Debug
    + Hash
    + Serialize
    + for<'a> Deserialize<'a>
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Display
    + for<'a> TryFrom<&'a TaggedBase64>
    + Into<TaggedBase64>
{
    /// The private key type for this signature algorithm
    type PrivateKey: Send
        + Sync
        + Sized
        + Clone
        + Debug
        + Eq
        + Serialize
        + for<'a> Deserialize<'a>
        + Hash;

    /// The type of the entry that contain both public key and stake value
    type StakeTableEntry: StakeTableEntryType<Self>
        + Send
        + Sync
        + Sized
        + Clone
        + Debug
        + Hash
        + Eq
        + Serialize
        + for<'a> Deserialize<'a>;

    /// The type of the quorum certificate parameters used for assembled signature
    type QcParams: Send + Sync + Sized + Clone + Debug + Hash;

    /// The type of the assembled signature, without `BitVec`
    type PureAssembledSignatureType: Send
        + Sync
        + Sized
        + Clone
        + Debug
        + Hash
        + PartialEq
        + Eq
        + Serialize
        + for<'a> Deserialize<'a>
        + Into<TaggedBase64>
        + for<'a> TryFrom<&'a TaggedBase64>;

    /// The type of the assembled qc: assembled signature + `BitVec`
    type QcType: Send
        + Sync
        + Sized
        + Clone
        + Debug
        + Hash
        + PartialEq
        + Eq
        + Serialize
        + for<'a> Deserialize<'a>;

    /// Type of error that can occur when signing data
    type SignError: std::error::Error + Send + Sync;

    // Signature type represented as a vec/slice of bytes to let the implementer handle the nuances
    // of serialization, to avoid Cryptographic pitfalls
    /// Validate a signature
    fn validate(&self, signature: &Self::PureAssembledSignatureType, data: &[u8]) -> bool;

    /// Produce a signature
    /// # Errors
    /// If unable to sign the data with the key
    fn sign(
        private_key: &Self::PrivateKey,
        data: &[u8],
    ) -> Result<Self::PureAssembledSignatureType, Self::SignError>;

    /// Produce a public key from a private key
    fn from_private(private_key: &Self::PrivateKey) -> Self;

    /// Serialize a public key to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a public key from bytes
    /// # Errors
    ///
    /// Will return `Err` if deserialization fails
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self>;

    /// Generate a new key pair
    fn generated_from_seed_indexed(seed: [u8; 32], index: u64) -> (Self, Self::PrivateKey);

    /// get the stake table entry from the public key and stake value
    fn stake_table_entry(&self, stake: u64) -> Self::StakeTableEntry;

    /// only get the public key from the stake table entry
    fn public_key(entry: &Self::StakeTableEntry) -> Self;

    /// get the public parameter for the assembled signature checking
    fn public_parameter(
        stake_entries: Vec<Self::StakeTableEntry>,
        threshold: U256,
    ) -> Self::QcParams;

    /// check the quorum certificate for the assembled signature
    fn check(real_qc_pp: &Self::QcParams, data: &[u8], qc: &Self::QcType) -> bool;

    /// get the assembled signature and the `BitVec` separately from the assembled signature
    fn sig_proof(signature: &Self::QcType) -> (Self::PureAssembledSignatureType, BitVec);

    /// assemble the signature from the partial signature and the indication of signers in `BitVec`
    fn assemble(
        real_qc_pp: &Self::QcParams,
        signers: &BitSlice,
        sigs: &[Self::PureAssembledSignatureType],
    ) -> Self::QcType;

    /// generates the genesis public key. Meant to be dummy/filler
    #[must_use]
    fn genesis_proposer_pk() -> Self;
}

impl SignatureKey for BLSPubKey {
    type PrivateKey = BLSPrivKey;
    type StakeTableEntry = StakeTableEntry<VerKey>;
    type QcParams =
        QcParams<BLSPubKey, <BLSOverBN254CurveSignatureScheme as SignatureScheme>::PublicParameter>;
    type PureAssembledSignatureType =
        <BLSOverBN254CurveSignatureScheme as SignatureScheme>::Signature;
    type QcType = (Self::PureAssembledSignatureType, BitVec);
    type SignError = SignatureError;

    #[instrument(skip(self))]
    fn validate(&self, signature: &Self::PureAssembledSignatureType, data: &[u8]) -> bool {
        // This is the validation for QC partial signature before append().
        BLSOverBN254CurveSignatureScheme::verify(&(), self, data, signature).is_ok()
    }

    fn sign(
        sk: &Self::PrivateKey,
        data: &[u8],
    ) -> Result<Self::PureAssembledSignatureType, Self::SignError> {
        BitVectorQc::<BLSOverBN254CurveSignatureScheme>::sign(
            &(),
            sk,
            data,
            &mut rand::thread_rng(),
        )
    }

    fn from_private(private_key: &Self::PrivateKey) -> Self {
        BLSPubKey::from(private_key)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed(self, &mut buf)
            .expect("Serialization should not fail.");
        buf
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ark_serialize::CanonicalDeserialize::deserialize_compressed(bytes)
            .map_err(|_| anyhow::anyhow!("Failed to deserialize BLS public key"))
    }

    fn generated_from_seed_indexed(seed: [u8; 32], index: u64) -> (Self, Self::PrivateKey) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed);
        hasher.update(&index.to_le_bytes());
        let new_seed = *hasher.finalize().as_bytes();
        let kp = KeyPair::generate(&mut ChaCha20Rng::from_seed(new_seed));
        (kp.ver_key(), kp.sign_key_ref().clone())
    }

    fn stake_table_entry(&self, stake: u64) -> Self::StakeTableEntry {
        StakeTableEntry {
            stake_key: *self,
            stake_amount: U256::from(stake),
        }
    }

    fn public_key(entry: &Self::StakeTableEntry) -> Self {
        entry.stake_key
    }

    fn public_parameter(
        stake_entries: Vec<Self::StakeTableEntry>,
        threshold: U256,
    ) -> Self::QcParams {
        QcParams {
            stake_entries,
            threshold,
            agg_sig_pp: (),
        }
    }

    fn check(real_qc_pp: &Self::QcParams, data: &[u8], qc: &Self::QcType) -> bool {
        let msg = GenericArray::from_slice(data);
        BitVectorQc::<BLSOverBN254CurveSignatureScheme>::check(real_qc_pp, msg, qc).is_ok()
    }

    fn sig_proof(signature: &Self::QcType) -> (Self::PureAssembledSignatureType, BitVec) {
        signature.clone()
    }

    fn assemble(
        real_qc_pp: &Self::QcParams,
        signers: &BitSlice,
        sigs: &[Self::PureAssembledSignatureType],
    ) -> Self::QcType {
        BitVectorQc::<BLSOverBN254CurveSignatureScheme>::assemble(real_qc_pp, signers, sigs)
            .expect("this assembling shouldn't fail")
    }

    fn genesis_proposer_pk() -> Self {
        let kp = KeyPair::generate(&mut ChaCha20Rng::from_seed([0u8; 32]));
        kp.ver_key()
    }
}
