//! Prelude module with concrete type instantiations for common use cases
//!
//! This module provides type aliases for MRE structs using BLS12-381 G1 curve,
//! allowing consumers to use the MRE functionality without specifying generic parameters.
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

use ark_bls12_381::G1Projective;

pub use crate::mre;
use crate::{
    feldman::FeldmanVss,
    traits::dkg::VerifiableSecretSharing,
    vess::{self, ShoupVess},
};

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
pub type Vess = ShoupVess<G1Projective>;

// TODO: (alex) simply re-export after VESS impl merged
/// Ciphertext of all secret shares in a single dealing
pub type VessCiphertext = vess::VessCiphertext<G1Projective>;

/// Verifiable secret sharing scheme used in DKG/resharing
pub type Vss = FeldmanVss<G1Projective>;

/// Commitment to a Shamir secret dealing
pub type VssCommitment = <FeldmanVss<G1Projective> as VerifiableSecretSharing>::Commitment;
