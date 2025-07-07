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
//! let sk = DecryptionKey::rand(rng);
//! let pk = EncryptionKey::from(&sk);
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

/// Encryption key using BLS12-381 G1 curve
pub type EncryptionKey = mre::EncryptionKey<G1Projective>;

/// Decryption key using BLS12-381 G1 curve  
pub type DecryptionKey = mre::DecryptionKey<G1Projective>;

/// Labeled decryption key using BLS12-381 G1 curve
pub type LabeledDecryptionKey = mre::LabeledDecryptionKey<G1Projective>;

/// Multi-recipient ciphertext using BLS12-381 G1 curve and SHA-256
pub type MultiRecvCiphertext = mre::MultiRecvCiphertext<G1Projective>;

/// Individual recipient ciphertext using BLS12-381 G1 curve and SHA-256  
pub type Ciphertext = mre::Ciphertext<G1Projective>;
