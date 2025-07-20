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

pub use crate::mre;
use crate::{
    DecryptionScheme,
    feldman::FeldmanVss,
    traits::{dkg::VerifiableSecretSharing, threshold_enc::ThresholdEncScheme},
    vess::{self, ShoupVess},
};
use anyhow::anyhow;
use ark_bls12_381::G1Projective;
use derive_more::From;
use std::sync::{Arc, RwLock};
pub use vess::VessCiphertext;

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

/// Verifiable secret sharing scheme used in DKG/resharing
pub type Vss = FeldmanVss<G1Projective>;

/// Commitment to a Shamir secret dealing
pub type VssCommitment = <FeldmanVss<G1Projective> as VerifiableSecretSharing>::Commitment;

/// Public encryption key in the threshold decryption scheme
pub type ThresholdEncKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;

/// A future available encryption key in the threshold decryption scheme,
/// updatable by a different thread/holder.
#[derive(Debug, Clone, From, Default)]
pub struct PendingThresholdEncKey(Arc<RwLock<Option<ThresholdEncKey>>>);

impl PendingThresholdEncKey {
    /// set the inner value, will block current thread until RwLock can be acquired
    pub fn set_key(&mut self, key: ThresholdEncKey) -> anyhow::Result<()> {
        let mut k = self.0.write().map_err(|e| anyhow!("{e:?}"))?;
        *k = Some(key);
        Ok(())
    }

    /// try to extract inner value if ready, incur cloning.
    /// Failure to acquire read lock, or posioned lock, or unready inner value will return None
    pub fn try_get(&self) -> Option<ThresholdEncKey> {
        self.0.try_read().ok()?.as_ref().cloned()
    }
}

/// Combiner key in the threshold decryption scheme
pub type ThresholdCombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;
/// Decryption key share in the threshold decryption scheme
pub type ThresholdDecKeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
