//! Multi-recipient Encryption (MRE) allows encryption of a vector of messages to all n parties.
//! Proposed as MEGa in <https://eprint.iacr.org/2022/506>, this code implements the simplified
//! variant in <https://eprint.iacr.org/2025/1175>.

use crate::serde_bridge::SerdeAs;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, SerializationError, serialize_to_vec,
};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};
use digest::Output;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Digest;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encryption key for an AD-only CCA-secure Public Key Encryption (PKE) scheme
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionKey<C: CurveGroup> {
    // u = g^alpha where alpha is the secret key
    #[serde_as(as = "SerdeAs")]
    pub(crate) u: C::Affine,
}

impl<C: CurveGroup> EncryptionKey<C> {
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut v = Vec::new();
        self.u.serialize_compressed(&mut v)?;
        Ok(v)
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self, SerializationError> {
        let u = C::Affine::deserialize_compressed(value)?;
        Ok(Self { u })
    }
}

impl<C: CurveGroup> From<C> for EncryptionKey<C> {
    fn from(proj: C) -> Self {
        Self {
            u: proj.into_affine(),
        }
    }
}

impl<C: CurveGroup> From<&DecryptionKey<C>> for EncryptionKey<C> {
    fn from(sk: &DecryptionKey<C>) -> Self {
        let u: C = C::generator().mul(&sk.alpha);
        Self::from(u)
    }
}

/// Decryption key for an AD-only CCA-secure Public Key Encryption (PKE) scheme
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct DecryptionKey<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    pub(crate) alpha: C::ScalarField,
}

impl<C: CurveGroup> DecryptionKey<C> {
    /// Similar to [`Self::rand()`] with thread_rng internally
    pub fn generate() -> Self {
        Self::rand(&mut ark_std::rand::thread_rng())
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        let alpha = C::ScalarField::rand(rng);
        Self { alpha }
    }

    /// label this key with system-wide info `node_idx`
    pub fn label(self, node_idx: usize) -> LabeledDecryptionKey<C> {
        let pk: EncryptionKey<C> = (&self).into();
        LabeledDecryptionKey {
            alpha: self.alpha,
            u: pk.u,
            node_idx,
        }
    }
}

/// [`DecryptionKey`] labeled with node index (while caching public key),
/// constructed via [`DecryptionKey::label()`]
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct LabeledDecryptionKey<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    pub(crate) alpha: C::ScalarField,
    pub(crate) u: C::Affine,
    pub(crate) node_idx: usize,
}

impl<C: CurveGroup> LabeledDecryptionKey<C> {
    /// Returns the node idx for this decryption key.
    pub fn node_idx(&self) -> usize {
        self.node_idx
    }

    /// Decryption for an individual ciphertext produced and extracted from [`encrypt()`]
    pub fn decrypt<H: Digest>(
        &self,
        ct: &Ciphertext<C, H>,
        aad: &[u8],
    ) -> Result<Vec<u8>, MultiRecvEncError> {
        // derive the shared DH value
        let edh = ct.epk.into_group().mul(&self.alpha);
        // derive the symmetric encryption key
        let k = derive_enc_key::<C, H>(self.node_idx, self.u, ct.epk, edh.into_affine(), aad)?;
        // finally, XOR with the ciphertext to decrypt
        let m = k.iter().zip(ct.ct.iter()).map(|(ki, c)| ki ^ c).collect();
        Ok(m)
    }
}
impl<C: CurveGroup> From<LabeledDecryptionKey<C>> for DecryptionKey<C> {
    fn from(lab_key: LabeledDecryptionKey<C>) -> Self {
        DecryptionKey {
            alpha: lab_key.alpha,
        }
    }
}

/// Ciphertext for multiple recipients in MRE scheme
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "H: Digest")]
pub struct MultiRecvCiphertext<C: CurveGroup, H: Digest = sha2::Sha256> {
    // the shared ephemeral public key (v:=g^beta in the paper)
    #[serde_as(as = "SerdeAs")]
    pub(crate) epk: C::Affine,
    // individual ciphertexts (e_i in the paper)
    pub(crate) cts: Vec<Output<H>>,
}

impl<C: CurveGroup, H: Digest> MultiRecvCiphertext<C, H> {
    /// Extract the recipient-specific ciphertext
    pub fn get_recipient_ct(&self, index: usize) -> Option<Ciphertext<C, H>> {
        self.cts.get(index).map(|ct| Ciphertext {
            epk: self.epk,
            ct: ct.clone(),
        })
    }
}

/// (Part of) [`MultiRecvCiphertext`] for a specific recipient.
/// Only appropriate construction is [`MultiRecvCiphertext::get_recipient_ct()`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext<C: CurveGroup, H: Digest = sha2::Sha256> {
    pub(crate) epk: C::Affine,
    pub(crate) ct: Output<H>,
}

/// Multi-Recipient Encryption (MRE) in <https://eprint.iacr.org/2025/1175>
///
/// # Parameters
/// - `recipients` and `messages` must be of the same length and implicitly indexed
/// - `aad` is the associated data
/// - `C` is the DL group, `H` is the choice of H_enc whose output space = message space
///   - preprocess messages to pad them to proper length before passing in
pub fn encrypt<'a, C, H, R, I>(
    recipients: I,
    messages: &[Vec<u8>],
    aad: &[u8],
    rng: &mut R,
) -> Result<MultiRecvCiphertext<C, H>, MultiRecvEncError>
where
    C: CurveGroup,
    H: Digest,
    R: Rng + CryptoRng,
    I: IntoIterator<Item = &'a EncryptionKey<C>>,
    I::IntoIter: ExactSizeIterator,
{
    // input validation
    let recipients_iter = recipients.into_iter();
    if messages.is_empty() {
        return Err(MultiRecvEncError::EmptyInput);
    }
    if recipients_iter.len() != messages.len() {
        return Err(MultiRecvEncError::MismatchedInputLength(
            recipients_iter.len(),
            messages.len(),
        ));
    }
    let expected_msg_len = <H as Digest>::output_size();
    for m in messages.iter() {
        if m.len() != expected_msg_len {
            return Err(MultiRecvEncError::MessageWrongSize(
                m.len(),
                expected_msg_len,
            ));
        }
    }

    // random sample a shared ephemeral keypair
    let esk = C::ScalarField::rand(rng);
    let epk = C::generator().mul(&esk);

    // generate recipient-specific ciphertext parts
    let cts = recipients_iter
        .zip(messages.iter())
        .enumerate()
        .map(|(idx, (pk, msg))| {
            // compute the ephemeral DH shared secret (w_j in the paper)
            let edh = pk.u.into_group().mul(&esk);
            // derive the symmetric encryption key
            let k = derive_enc_key::<C, H>(
                idx,
                pk.u.to_owned(),
                epk.into_affine(),
                edh.into_affine(),
                aad,
            )?;

            // TODO(alex): use SIMD vectorized XOR when `std::simd` move out of nightly,
            // or rayon as an intermediate improvement
            let ct = Output::<H>::from_iter(k.iter().zip(msg.iter()).map(|(ki, m)| ki ^ m));
            Ok(ct)
        })
        .collect::<Result<Vec<_>, MultiRecvEncError>>()?;
    Ok(MultiRecvCiphertext {
        epk: epk.into_affine(),
        cts,
    })
}

// deriving the symmetric encryption/decryption key
// k := H_enc(j, pk_j, epk, dh_j, aad)
fn derive_enc_key<C: CurveGroup, H: Digest>(
    idx: usize,
    pk: C::Affine,
    epk: C::Affine,
    dh: C::Affine,
    aad: &[u8],
) -> Result<Output<H>, MultiRecvEncError> {
    let mut hasher = H::new();
    hasher.update(idx.to_le_bytes());
    hasher.update(serialize_to_vec![pk, epk, dh]?);
    hasher.update(aad);
    let key = hasher.finalize();
    Ok(key)
}

/// Error types for Multi-Recipient Encryption scheme
#[derive(Error, Debug)]
pub enum MultiRecvEncError {
    #[error("unexpected empty input")]
    EmptyInput,
    #[error("expect the same input lengths, but got {0} and {1}")]
    MismatchedInputLength(usize, usize),
    #[error("message length {0} should equal hash output length {1}")]
    MessageWrongSize(usize, usize),
    #[error("de/serialization err: {0}")]
    SerdeError(String),
}

impl From<ark_serialize::SerializationError> for MultiRecvEncError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerdeError(e.to_string())
    }
}

impl From<bs58::decode::Error> for MultiRecvEncError {
    fn from(e: bs58::decode::Error) -> Self {
        Self::SerdeError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter::repeat_with};

    use ark_bls12_381::G1Projective;
    use ark_std::rand;

    use super::*;
    type H = sha2::Sha256;

    #[test]
    fn test_mre_correctness() {
        let rng = &mut rand::thread_rng();
        let n = 10; // num of recipients
        let recv_sks: Vec<DecryptionKey<G1Projective>> =
            repeat_with(|| DecryptionKey::rand(rng)).take(n).collect();
        // collecting into a BTreeSet to demonstrate flexible encrypt() input type
        let recv_pks: BTreeMap<usize, EncryptionKey<G1Projective>> = recv_sks
            .iter()
            .enumerate()
            .map(|(i, sk)| (i, EncryptionKey::from(sk)))
            .collect();
        let labeled_sks: Vec<LabeledDecryptionKey<G1Projective>> = recv_sks
            .into_iter()
            .enumerate()
            .map(|(i, sk)| sk.label(i))
            .collect();
        let msgs = repeat_with(|| rng.r#gen::<[u8; 32]>().to_vec())
            .take(n)
            .collect::<Vec<_>>();
        let aad = b"Alice";

        let mre_ct = encrypt::<G1Projective, H, _, _>(recv_pks.values(), &msgs, aad, rng).unwrap();
        for i in 0..n {
            let ct = mre_ct.get_recipient_ct(i).unwrap();
            assert_eq!(
                labeled_sks[i]
                    .decrypt::<H>(&ct, aad)
                    .expect("decryption failed"),
                msgs[i]
            );

            // soundness test: any wrong index, sk, ciphertext, or associated data should fail
            // Test with wrong index (if available)
            if let Some(_wrong_labeled_sk) = labeled_sks.get(i + 1) {
                // Create a new labeled key with wrong index but correct secret
                let wrong_idx_sk = DecryptionKey {
                    alpha: labeled_sks[i].alpha,
                }
                .label(i + 1);
                assert_ne!(wrong_idx_sk.decrypt::<H>(&ct, aad).unwrap(), msgs[i]);
            }
            // Test with wrong secret key (if available)
            if let Some(wrong_labeled_sk) = labeled_sks.get(i + 1) {
                assert_ne!(wrong_labeled_sk.decrypt::<H>(&ct, aad).unwrap(), msgs[i]);
            }
            // Test with wrong ciphertext (if available)
            if let Some(wrong_ct) = mre_ct.get_recipient_ct(i + 1) {
                assert_ne!(
                    labeled_sks[i].decrypt::<H>(&wrong_ct, aad).unwrap(),
                    msgs[i]
                );
            }
            // Test with wrong associated data
            assert_ne!(labeled_sks[i].decrypt::<H>(&ct, b"Bob").unwrap(), msgs[i]);
        }
    }

    #[test]
    fn test_serde() {
        let rng = &mut rand::thread_rng();
        let sk = DecryptionKey::<G1Projective>::rand(rng);
        let pk = EncryptionKey::from(&sk);

        let bytes = bincode::serde::encode_to_vec(&sk, bincode::config::standard()).unwrap();
        assert_eq!(
            bincode::serde::decode_from_slice::<DecryptionKey::<G1Projective>, _>(
                &bytes,
                bincode::config::standard()
            )
            .unwrap()
            .0,
            sk
        );

        let bytes = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        assert_eq!(
            bincode::serde::decode_from_slice::<EncryptionKey::<G1Projective>, _>(
                &bytes,
                bincode::config::standard()
            )
            .unwrap()
            .0,
            pk
        );

        let json = serde_json::to_string(&sk).unwrap();
        assert_eq!(sk, serde_json::from_str(&json).unwrap());

        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(pk, serde_json::from_str(&json).unwrap());
    }
}
