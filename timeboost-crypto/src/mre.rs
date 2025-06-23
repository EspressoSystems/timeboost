//! Multi-recipient Encryption (MRE) allows encryption of a vector of message to all n parties.
//! Proposed as MEGa in <https://eprint.iacr.org/2022/506>, this code implements the simplified
//! variant in <https://eprint.iacr.org/2025/1175>.

use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_serialize::serialize_to_vec;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};
use digest::Output;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

/// Ciphertext for multiple recipients in MRE scheme
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiRecvCiphertext<C: CurveGroup, H: Digest> {
    // the shared ephemeral public key (v:=g^beta in the paper)
    epk: C::Affine,
    // individual ciphertexts (e_i in the paper)
    cts: Vec<Output<H>>,
}

impl<C: CurveGroup, H: Digest> MultiRecvCiphertext<C, H> {
    /// Extract the recipient-specific ciphertext
    pub fn get_recipient_ct(&self, index: usize) -> Option<SingleRecvCiphertext<C, H>> {
        self.cts.get(index).map(|ct| SingleRecvCiphertext {
            epk: self.epk,
            ct: ct.clone(),
        })
    }
}

/// (Part of) [`MultiRecvCiphertext`] for a specific recipient.
/// Only appropriate construction is [`MultiRecvCiphertext::get_recipient_ct()`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleRecvCiphertext<C: CurveGroup, H: Digest> {
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
pub fn encrypt<'pk, 'msg, C, H, R>(
    recipients: impl IntoIterator<Item = &'pk C::Affine>,
    messages: impl IntoIterator<Item = &'msg Vec<u8>>,
    aad: &[u8],
    rng: &mut R,
) -> Result<MultiRecvCiphertext<C, H>, MultiRecvEncError>
where
    C: CurveGroup,
    H: Digest,
    R: Rng + CryptoRng,
{
    // random sample a shared ephemeral keypair
    let esk = <C::Config as CurveConfig>::ScalarField::rand(rng);
    let epk = C::generator().mul(&esk);

    // generate recipient-specific ciphertext parts
    let mut pk_iter = recipients.into_iter();
    let mut msg_iter = messages.into_iter();
    let expected_msg_len = <H as Digest>::output_size();

    let cts = pk_iter
        .by_ref()
        .zip(msg_iter.by_ref())
        .enumerate()
        .map(|(idx, (pk, msg))| {
            if msg.len() != expected_msg_len {
                return Err(MultiRecvEncError::MessageWrongSize(
                    msg.len(),
                    expected_msg_len,
                ));
            }
            // compute the ephemeral DH shared secret (w_j in the paper)
            let edh = pk.into_group().mul(&esk);
            // derive the symmetric encryption key
            let k = derive_enc_key::<C, H>(
                idx,
                pk.to_owned(),
                epk.into_affine(),
                edh.into_affine(),
                aad,
            )?;

            // TODO(alex): use SIMD vectorized XOR when `std::simd` move out of nightly,
            // or rayon as an intermediate improvement
            let ct = Output::<H>::from_iter(k.iter().zip(msg).map(|(ki, m)| ki ^ m));
            Ok(ct)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // check if two iterators have left-overs (thus mismatched length)
    match (pk_iter.next(), msg_iter.next()) {
        (None, None) => Ok(MultiRecvCiphertext {
            epk: epk.into_affine(),
            cts,
        }),
        _ => Err(MultiRecvEncError::MismatchedInputLength),
    }
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

/// Decryption for an individual ciphertext produced and extracted from [`encrypt()`]
pub fn decrypt<C, H>(
    index: usize,
    recv_sk: &<C::Config as CurveConfig>::ScalarField,
    ct: &SingleRecvCiphertext<C, H>,
    aad: &[u8],
) -> Result<Vec<u8>, MultiRecvEncError>
where
    C: CurveGroup,
    H: Digest,
{
    let pk = C::generator().mul(recv_sk);
    // derive the shared DH value
    let edh = ct.epk.into_group().mul(recv_sk);
    // derive the symmetric encryption key
    let k = derive_enc_key::<C, H>(index, pk.into_affine(), ct.epk, edh.into_affine(), aad)?;
    // finally, XOR with the ciphertext to decrypt
    let m = k.iter().zip(ct.ct.iter()).map(|(ki, c)| ki ^ c).collect();
    Ok(m)
}

/// Error types for Multi-Recipient Encryption scheme
#[derive(Error, Debug)]
pub enum MultiRecvEncError {
    #[error("expect the same input lengths")]
    MismatchedInputLength,
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

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_std::rand;

    use super::*;
    type H = sha2::Sha256;

    #[test]
    fn test_mre_correctness() {
        let rng = &mut rand::thread_rng();
        let n = 10; // num of recipients
        let recv_sks: Vec<Fr> = repeat_with(|| Fr::rand(rng)).take(n).collect();
        let recv_pks: Vec<G1Affine> = recv_sks
            .iter()
            .map(|sk| (G1Projective::generator() * sk).into_affine())
            .collect();
        let msgs = repeat_with(|| rng.r#gen::<[u8; 32]>().to_vec())
            .take(n)
            .collect::<Vec<_>>();
        let aad = b"Alice";

        let mre_ct = encrypt::<G1Projective, H, _>(&recv_pks, &msgs, aad, rng).unwrap();
        for i in 0..n {
            let ct = mre_ct.get_recipient_ct(i).unwrap();
            assert_eq!(
                decrypt::<G1Projective, H>(i, &recv_sks[i], &ct, aad).expect("decryption failed"),
                msgs[i]
            );

            // soundness test: any wrong index, sk, ciphertext, or associated data should fail
            assert_ne!(
                decrypt::<G1Projective, H>(i + 1, &recv_sks[i], &ct, aad).unwrap(),
                msgs[i]
            );
            if let Some(wrong_sk) = recv_sks.get(i + 1) {
                assert_ne!(
                    decrypt::<G1Projective, H>(i, wrong_sk, &ct, aad).unwrap(),
                    msgs[i]
                );
            }
            if let Some(wrong_ct) = mre_ct.get_recipient_ct(i + 1) {
                assert_ne!(
                    decrypt::<G1Projective, H>(i, &recv_sks[i], &wrong_ct, aad).unwrap(),
                    msgs[i]
                );
            }
            assert_ne!(
                decrypt::<G1Projective, H>(i, &recv_sks[i], &ct, b"Bob").unwrap(),
                msgs[i]
            );
        }
    }
}
