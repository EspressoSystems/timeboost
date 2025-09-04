//! Prelude module with concrete type instantiations for common use cases
//!
//! This module provides type aliases for MRE and TPKE structs using BLS12-381 G1 curve,
//! allowing consumers to use the encryption schemes without specifying generic parameters.
//!
//! # Example
//! ```
//! use timeboost_crypto::prelude::*;
//! use timeboost_crypto::mre::encrypt;
//! use ark_std::rand;
//!
//! let rng = &mut rand::thread_rng();
//! let sk = DkgDecKey::rand(rng);
//! let pk = DkgEncKey::from(&sk);
//! let node_idx = 0;
//! let labeled_sk = sk.label(node_idx);
//!
//! let recipients = vec![pk];
//! let messages = vec![vec![0u8; 32]];
//! let aad = b"example";
//!
//! // type annotation MultiRecvCiphertext helps `encrypt<C, H, R>()` to infer generic types
//! let mre_ct: MultiRecvCiphertext = encrypt(&recipients, &messages, aad, rng).unwrap();
//!
//! // extract out the part of the ciphertext specific for this node.
//! let ciphertext = mre_ct.get_recipient_ct(node_idx).unwrap();
//!
//! // Finally, decrypt to the original plaintext
//! let plaintext = labeled_sk.decrypt(&ciphertext, aad).unwrap();
//! assert_eq!(plaintext, messages[node_idx]);
//! ```

use ark_bls12_381::{G1Projective, g1::Config};
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::Sha256;
use spongefish::DigestBridge;

use crate::{feldman, mre, sg_encryption, vess};

pub use crate::feldman::FeldmanVssPublicParam;
pub use crate::sg_encryption::Plaintext;
pub use crate::traits::dkg::{KeyResharing, VerifiableSecretSharing};
pub use crate::traits::tpke::{ThresholdEncError, ThresholdEncScheme};
pub use crate::vess::{VessCiphertext, VessError};

type H = Sha256;
type D = DigestBridge<H>;
type H2C = MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<H>, WBMap<Config>>;

/// Encryption key used in the DKG and key resharing for secure communication
pub type DkgEncKey = mre::EncryptionKey<G1Projective>;

/// Decryption key used in the DKG and key resharing for secure communication
pub type DkgDecKey = mre::DecryptionKey<G1Projective>;

/// [`DkgDecryptionKey`] labeled with key/node ID
pub type LabeledDkgDecKey = mre::LabeledDecryptionKey<G1Projective>;

/// Multi-recipient ciphertext using BLS12-381 G1 curve and SHA-256
pub type MultiRecvCiphertext = mre::MultiRecvCiphertext<G1Projective>;

/// Individual recipient ciphertext for encryption/decryption key used in DKG or key resharing
pub type DkgCiphertext = mre::Ciphertext<G1Projective>;

/// Verifiable Encrypted Secret Sharing (VESS) scheme used in DKG/resharing
pub type Vess = vess::ShoupVess<G1Projective>;

/// Verifiable secret sharing scheme used in DKG/resharing
pub type Vss = feldman::FeldmanVss<G1Projective>;

/// Secret value in the verifiable secret sharing scheme.
pub type VssSecret = <Vss as VerifiableSecretSharing>::Secret;

/// Secret share of the verifiable secret sharing scheme.
pub type VssShare = <Vss as VerifiableSecretSharing>::SecretShare;

/// Commitment to a Shamir secret dealing
pub type VssCommitment = <Vss as VerifiableSecretSharing>::Commitment;

/// Threshold Public Key Encryption (TPKE) scheme.
pub type ThresholdScheme = sg_encryption::ShoupGennaro<G1Projective, H, D, H2C>;

/// Public encryption key in the threshold decryption scheme
pub type ThresholdEncKey =
    <sg_encryption::ShoupGennaro<G1Projective, H, D, H2C> as ThresholdEncScheme>::PublicKey;

/// Combiner key in the threshold decryption scheme
pub type ThresholdCombKey =
    <sg_encryption::ShoupGennaro<G1Projective, H, D, H2C> as ThresholdEncScheme>::CombKey;

/// Decryption key share in the threshold decryption scheme
pub type ThresholdKeyShare =
    <sg_encryption::ShoupGennaro<G1Projective, H, D, H2C> as ThresholdEncScheme>::KeyShare;

/// Decryption share in the threshold decryption scheme
pub type ThresholdDecShare =
    <sg_encryption::ShoupGennaro<G1Projective, H, D, H2C> as ThresholdEncScheme>::DecShare;

/// Ciphertext for threshold decryption scheme
pub type ThresholdCiphertext =
    <sg_encryption::ShoupGennaro<G1Projective, H, D, H2C> as ThresholdEncScheme>::Ciphertext;
