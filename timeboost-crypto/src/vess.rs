//! Verifiable Encrypted Secret Sharing (VESS) schemes

use std::num::NonZeroU32;

use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, serialize_to_vec};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
};
use sha2::Digest;
use thiserror::Error;

use crate::{
    feldman::{FeldmanVss, FeldmanVssPublicParam},
    mre::{self, MultiRecvCiphertext},
    traits::dkg::VerifiableSecretSharing,
};

/// Implementation of [Shoup25](https://eprint.iacr.org/2025/1175)
///
/// dev note: we fix MultiReceiver encryption choice, default to Feldman VSS, leave DLog Group
/// choice open as a generic parameter.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ShoupVess<C, H = sha2::Sha256, VSS = FeldmanVss<C>>
where
    C: CurveGroup,
    H: Digest,
    VSS: VerifiableSecretSharing<Secret = C::ScalarField>,
{
    /// repetition param, N in paper
    num_repetition: usize,
    /// verifier "open" subset S, M=|S| in paper
    subset_size: usize,
    vss_pp: VSS::PublicParam,
    _group: PhantomData<C>,
    _mre_hash: PhantomData<H>,
}

/// Ciphertext of [`ShoupVess`] scheme, verifiable by itself as its constructed as a sigma proof
#[derive(Debug, Clone)]
pub struct VessCiphertext<C: CurveGroup> {
    // TODO(alex): update this struct in phase 2
    pub(crate) mre_ct: MultiRecvCiphertext<C>,
}

impl<C: CurveGroup> ShoupVess<C> {
    /// init with system parameters corresponding to a faster variant with larger dealing
    pub fn new_fast(vss_threshold: NonZeroU32, vss_num_shares: NonZeroU32) -> Self {
        let vss_pp = FeldmanVssPublicParam::new(vss_threshold, vss_num_shares);
        Self {
            num_repetition: 132,
            subset_size: 64,
            vss_pp,
            _group: PhantomData,
            _mre_hash: PhantomData,
        }
    }

    /// init with system parameters corresponding to a slower variant with shorter dealing
    pub fn new_short(vss_threshold: NonZeroU32, vss_num_shares: NonZeroU32) -> Self {
        let vss_pp = FeldmanVssPublicParam::new(vss_threshold, vss_num_shares);
        Self {
            num_repetition: 250,
            subset_size: 30,
            vss_pp,
            _group: PhantomData,
            _mre_hash: PhantomData,
        }
    }

    /// Encrypt secret sharing from `VSS::share()` with publicly verifiable proof.
    /// In our specific Shoup25 VESS, the ciphertext itself is a cut-and-choose style sigma proof,
    /// thus no extra dedicated proof in the output.
    ///
    /// # Parameters
    /// - `aad`: associated data (e.g. domain separator for this encryption, round number & context)
    ///
    /// TODO(alex): currently non-verifiable, add cut-and-choose logic later
    pub fn encrypted_shares<R>(
        &self,
        recipients: &[C::Affine],
        secret: C::ScalarField,
        aad: &[u8],
        rng: &mut R,
    ) -> Result<
        (
            VessCiphertext<C>,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        ),
        VessError,
    >
    where
        R: Rng + CryptoRng,
    {
        let n = self.vss_pp.n.get() as usize;
        if recipients.len() != n {
            return Err(VessError::WrongRecipientsLength(n, recipients.len()));
        }

        // compute the shares
        let (shares, comm) = FeldmanVss::<C>::share(&self.vss_pp, rng, secret);

        // encrypt the secret shares
        let shares_bytes = shares
            .into_iter()
            .map(|s| serialize_to_vec![s])
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        let mre_ct = mre::encrypt::<C, sha2::Sha256, R>(recipients, &shares_bytes, aad, rng)?;

        let ct = VessCiphertext { mre_ct };
        Ok((ct, comm))
    }

    /// Verify if the ciphertext (for all recipients) correctly encrypting valid secret shares,
    /// verifiable by anyone.
    pub fn verify(
        &self,
        _ct: &VessCiphertext<C>,
        _comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
    ) -> Result<bool, VessError> {
        todo!("to be implemented in phase 2")
    }

    /// Decrypt as the `node_idx`-th receiver with decryption key `recv_sk`
    pub fn decrypt_share(
        &self,
        node_idx: usize,
        recv_sk: &C::ScalarField,
        ct: &VessCiphertext<C>,
        aad: &[u8],
    ) -> Result<C::ScalarField, VessError> {
        let n = self.vss_pp.n.get() as usize;
        let recv_ct = ct
            .mre_ct
            .get_recipient_ct(node_idx)
            .ok_or(VessError::IndexOutOfBound(n, node_idx))?;

        let pt = mre::decrypt::<C, sha2::Sha256>(node_idx, recv_sk, &recv_ct, aad)?;
        let share: C::ScalarField = CanonicalDeserialize::deserialize_compressed(&*pt)?;

        Ok(share)
    }
}

/// Error related to VESS scheme
#[derive(Error, Debug)]
pub enum VessError {
    #[error("mre failed: {0}")]
    Mre(#[from] mre::MultiRecvEncError),
    #[error("serde err: {0}")]
    SerdeError(String),
    #[error("num of recipients, expect: {0}, got: {1}")]
    WrongRecipientsLength(usize, usize),
    #[error("max length: {0}, access index: {1}")]
    IndexOutOfBound(usize, usize),
}

impl From<ark_serialize::SerializationError> for VessError {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Self::SerdeError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_std::{
        UniformRand,
        rand::{SeedableRng, rngs::StdRng},
    };
    use std::iter::repeat_with;

    type H = sha2::Sha256;
    type Vss = FeldmanVss<G1Projective>;

    fn test_vess_correctness_helper(vess: ShoupVess<G1Projective, H, Vss>) {
        let rng = &mut StdRng::seed_from_u64(0);
        let secret = Fr::rand(rng);
        let n = vess.vss_pp.n.get() as usize;

        let recv_sks: Vec<Fr> = repeat_with(|| Fr::rand(rng)).take(n).collect();
        let recv_pks: Vec<G1Affine> = recv_sks
            .iter()
            .map(|sk| (G1Projective::generator() * sk).into_affine())
            .collect();

        let aad = b"Associated data";
        let (ct, comm) = vess.encrypted_shares(&recv_pks, secret, aad, rng).unwrap();

        for (node_idx, recv_sk) in recv_sks.iter().enumerate() {
            let share = vess.decrypt_share(node_idx, recv_sk, &ct, aad).unwrap();
            assert!(Vss::verify(&vess.vss_pp, node_idx, &share, &comm).unwrap());
        }
    }

    #[test]
    fn test_vess_correctness() {
        test_vess_correctness_helper(ShoupVess::new_fast(
            NonZeroU32::new(5).unwrap(),
            NonZeroU32::new(13).unwrap(),
        ));
        test_vess_correctness_helper(ShoupVess::new_short(
            NonZeroU32::new(10).unwrap(),
            NonZeroU32::new(20).unwrap(),
        ));
    }
}
