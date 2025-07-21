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
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
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
#[derive(Debug, Clone, Default)]
pub struct PendingThresholdEncKey {
    key: Arc<RwLock<Option<ThresholdEncKey>>>,
    done: Arc<AtomicBool>,
}

impl PendingThresholdEncKey {
    /// Set the inner value. If the key has already been set by another thread,
    /// this will return early without acquiring the lock or setting the key again.
    /// Only the first successful call will actually set the key.
    pub fn set_key(&self, key: ThresholdEncKey) -> anyhow::Result<()> {
        // Fast path: check if already set without acquiring any locks
        if self.is_ready() {
            return Ok(());
        }

        // Slow path: try to set the key
        let mut k = self.key.write().map_err(|e| anyhow!("{e:?}"))?;

        // Double-check after acquiring the lock (in case another thread set it)
        if self.done.load(Ordering::Acquire) {
            return Ok(());
        }

        *k = Some(key);
        self.done.store(true, Ordering::Release);
        Ok(())
    }

    /// Try to extract inner value if ready, incurring cloning.
    /// Fast path: if not set, return None immediately without acquiring any locks.
    /// Failure to acquire read lock, or poisoned lock, or unready inner value will return None
    pub fn try_get(&self) -> Option<ThresholdEncKey> {
        // Fast path: check if set without acquiring any locks
        if !self.is_ready() {
            return None;
        }

        // Slow path: try to read the key
        self.key.try_read().ok()?.as_ref().cloned()
    }

    /// Check if the key has been set without trying to read it.
    /// This is a very fast, lock-free operation.
    pub fn is_ready(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

/// Combiner key in the threshold decryption scheme
pub type ThresholdCombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;
/// Decryption key share in the threshold decryption scheme
pub type ThresholdDecKeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
