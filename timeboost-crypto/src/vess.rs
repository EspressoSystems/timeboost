//! Verifiable Encrypted Secret Sharing (VESS) schemes

use std::num::NonZeroU32;

use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, serialize_to_vec};
use ark_std::{
    UniformRand,
    marker::PhantomData,
    rand::{CryptoRng, Rng, SeedableRng},
};
use num_integer::binomial;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::Digest;
use spongefish::{
    ByteWriter, DefaultHash, UnitToBytes,
    codecs::arkworks_algebra::{
        FieldDomainSeparator, FieldToUnit, GroupDomainSeparator, GroupToUnit,
    },
};
use thiserror::Error;

use crate::{
    feldman::{FeldmanVss, FeldmanVssPublicParam},
    mre::{self, MultiRecvCiphertext},
    traits::dkg::VerifiableSecretSharing,
};

/// Implementation of [Shoup25](https://eprint.iacr.org/2025/1175)
///
/// This struct serves as the main handle to access all algorithms in a VESS scheme, storing public
/// parameters in `self`.
///
/// dev note: we fix MultiReceiver encryption choice, default to Feldman VSS, leave DLog Group
/// choice open as a generic parameter.
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
    /// public parameter for the underlying VSS
    vss_pp: VSS::PublicParam,

    _group: PhantomData<C>,
    _mre_hash: PhantomData<H>,
}

/// Ciphertext of [`ShoupVess`] scheme, verifiable by itself as its constructed as a sigma proof
#[derive(Debug, Clone)]
pub struct VessCiphertext {
    /// Sigma proof transcript (which contains encrypted MRE ciphertexts to be decrypted)
    transcript: Vec<u8>,
}

impl<C: CurveGroup> ShoupVess<C> {
    /// init with system parameters corresponding to a faster variant with larger dealing
    ///
    /// # 127+ bit security instead of strictly =128 bit
    /// parameter different from paper, see rationale in [`Self::map_subset_seed()`]
    pub fn new_fast(vss_threshold: NonZeroU32, vss_num_shares: NonZeroU32) -> Self {
        let vss_pp = FeldmanVssPublicParam::new(vss_threshold, vss_num_shares);
        Self {
            num_repetition: 132,
            subset_size: 60,
            vss_pp,
            _group: PhantomData,
            _mre_hash: PhantomData,
        }
    }

    /// init with system parameters corresponding to a slower variant with shorter dealing
    ///
    /// # 127+ bit security instead of strictly =128 bit
    /// parameter different from paper, see rationale in [`Self::map_subset_seed()`]
    pub fn new_short(vss_threshold: NonZeroU32, vss_num_shares: NonZeroU32) -> Self {
        let vss_pp = FeldmanVssPublicParam::new(vss_threshold, vss_num_shares);
        Self {
            num_repetition: 245,
            subset_size: 30,
            vss_pp,
            _group: PhantomData,
            _mre_hash: PhantomData,
        }
    }

    /// construct the transcript pattern in the interactive proof for Fiat-Shamir transformation.
    /// `aad`: associated data for context/session identifier
    /// IOPattern binds all public parameters including N, M, t, n, aad, to avoid weak FS attack.
    fn io_pattern(&self, aad: &[u8]) -> spongefish::DomainSeparator {
        let t = self.vss_pp.t.get() as usize;
        let n = self.vss_pp.n.get() as usize;

        let mut ds = spongefish::DomainSeparator::<DefaultHash>::new(&format!(
            "vess-ad-{}",
            bs58::encode(aad).into_string()
        ));
        ds = GroupDomainSeparator::<C>::add_points(ds, t, "C")
            .absorb(32, "h")
            // 16 random bytes for subset seed, see [`Self::map_subset_seed()`]
            .squeeze(16, "s");
        // for k \in S, rho_k = (shifted_poly_k; mre_ct_k)
        for _ in 0..self.subset_size {
            // shifted_poly_k or \omega_k'' in paper
            ds = FieldDomainSeparator::<C::ScalarField>::add_scalars(ds, t, "shifted_poly_k");
            // ephemeral pk part of the MRE ciphertext or v_k in paper
            ds = GroupDomainSeparator::<C>::add_points(ds, 1, "epk_k");
            // symmetric ciphertexts (cts) part of the MRE ciphertext or e_k1,..e_kn in paper
            // each e_ki has the same length as the H=Sha256's output size which is 32 bytes
            ds = ds.absorb(n * 32, "cts_k");
        }
        // for k \notin S, rho_k = r_k (32 bytes is sufficiently large seed space)
        ds.absorb((self.num_repetition - self.subset_size) * 32, "all_r_k")
    }

    /// map a seed (16 bytes) to |S|-length vec of selected indices in range [0, N),
    /// where |S| is the subset size, and N is the total number of repetitions.
    ///
    /// # Design
    ///
    /// Let T = binomial(N, |S|) or "N choose |S|", the number of possible subset S.
    /// To ensure exactly |S|-sized (w.h.p.) subset, we takes u128 (16 random bytes from transcript)
    /// and mod T to get an index in range [0, T) indicating a subset in the entire subset space.
    /// Then we use a bijective unrank procedure to identify the exact subset; this procedure
    /// is efficient with runtime cost O(|s|).
    ///
    /// ## Unranking map
    ///
    /// Every |S|-sized subset corresponds to a unique lexicographic position among the
    /// binom(N, |S|) possible subsets. The (unoptimized) pseudocode is as follows:
    ///
    /// Initialize: current = 0, n = N, k = |S|
    /// while k > 0:
    ///     let c = binom(n - 1, k - 1)
    ///     if r < c:
    ///         include current in subset
    ///         decrement k
    ///     else:
    ///         subtract c from r
    ///     increment current
    ///     decrement n
    ///
    /// We can optimize -- avoid full computation of binom(n-1, k-1) in each iteration by
    /// reusing the result from last iteration which is either binom(n, k) or binom(n, k-1)
    ///
    /// The concrete implementation is in [`unrank_combinations()`].
    ///
    /// # Modifications on N and |S|
    ///
    /// We slightly deviate from the paper on the parameter setting for N and |S| (or M in paper).
    /// (N, |S|) = (132, 64) and (250, 30) give
    /// log2(binomial(132, 64)) = 128.06 bit and log2(binomimal(250, 30)) = 128.64 bit security.
    /// but then our (mod T) would have to be done in bigint rather than primitive types,
    /// to keep log2(T)<=128, we decide to down-scale these parameters little bit to:
    /// (N, |S|) = (132, 60) and (245, 30) which give 127.37 bit and 127.72 bit security.
    /// We still have ~128-bit security, and the mod reduction bias is, < 2^-127, negligible.
    fn map_subset_seed(&self, seed: [u8; 16]) -> Vec<usize> {
        let subset = unrank_combinations(
            self.num_repetition as u128,
            self.subset_size as u128,
            u128::from_le_bytes(seed),
        );
        debug_assert_eq!(subset.len(), self.subset_size as usize);
        subset
    }

    /// Encrypt secret sharing from `VSS::share()` with publicly verifiable proof.
    /// In our specific Shoup25 VESS, the ciphertext itself is a cut-and-choose style sigma proof,
    /// thus no extra dedicated proof in the output.
    ///
    /// # Parameters
    /// - `aad`: associated data (e.g. domain separator for this encryption, round number & context)
    ///
    /// # Choices
    /// - H_choose: SpongeFish's sponge-based permutation (specifically, DefaultHash=Keccak)
    /// - H_compress: sha2::Sha256
    /// - H_expand: we slightly deviate from the paper to better align with our APIs: instead of
    ///   H_expand some expansion-seed r_k, we directly use r_k to seed a SeedableRng, this rng is
    ///   used to first randomly sample a secret (basically \omega'_k(0) in paper), then passed to
    ///   `FeldmanVss::share(pp, rng, secret)` where the rest of coeffs are sampled, then passed to
    ///   `mre::encrypt(.., rng)` for sampling the ephemeral sk, or beta_k in paper. Effectively,
    ///   step 1.a is split as two internal steps in the two APIs above. r_k is 32 bytes and
    ///   SpongeFish's built-in prover private coin toss.
    /// - random subset seed s: see [`Self::map_subset_seed()`]
    pub fn encrypted_shares(
        &self,
        recipients: &[C::Affine],
        secret: C::ScalarField,
        aad: &[u8],
    ) -> Result<
        (
            VessCiphertext,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        ),
        VessError,
    > {
        // input validation
        let n = self.vss_pp.n.get() as usize;
        if recipients.len() != n {
            return Err(VessError::WrongRecipientsLength(n, recipients.len()));
        }

        let mut prover_state = self.io_pattern(aad).to_prover_state();

        // r_k: expansion seed from prover private coin
        let mut seeds = vec![];
        for _ in 0..self.num_repetition {
            let r_k = prover_state.rng().r#gen::<[u8; 32]>();
            seeds.push(r_k);
        }

        // prepare N random dealings (Shamir poly + Feldman commitment + MRE ciphertext)
        let dealings: Vec<(
            DensePolynomial<C::ScalarField>,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
            MultiRecvCiphertext<C, sha2::Sha256>,
        )> = seeds
            .par_iter()
            .map(|r| {
                let mut rng = ChaCha20Rng::from_seed(*r);
                let vss_secret = C::ScalarField::rand(&mut rng);

                let (poly, comm) =
                    FeldmanVss::<C>::rand_poly_and_commit(&self.vss_pp, vss_secret, &mut rng);
                let serialized_shares: Vec<Vec<u8>> =
                    FeldmanVss::<C>::compute_serialized_shares(&self.vss_pp, &poly).collect();

                // TODO: use aad'= aad | k instead?
                let mre_ct = mre::encrypt::<C, sha2::Sha256, _>(
                    recipients,
                    &serialized_shares,
                    aad,
                    &mut rng,
                )?;
                Ok((poly, comm, mre_ct))
            })
            .collect::<Result<_, VessError>>()?;

        // compute h:= H_compress(aad, dealings)
        let mut hasher = sha2::Sha256::new();
        hasher.update(aad);
        for theta in dealings.iter() {
            hasher.update(serialize_to_vec![theta.1]?);
            hasher.update(theta.2.to_bytes());
        }
        let h = hasher.finalize();

        // commit the actual/original secret poly, (`comm` is C in paper)
        let (poly, comm) =
            FeldmanVss::<C>::rand_poly_and_commit(&self.vss_pp, secret, prover_state.rng());

        // prover send C and h to the verifier
        prover_state.add_points(
            &comm
                .iter()
                .map(|c: &C::Affine| c.into_group())
                .collect::<Vec<_>>(),
        )?;
        prover_state.add_bytes(&h)?;

        // verifier challenge for random subset seed s, see `Self::map_subset_seed()` about
        // the rationale for 16 random bytes per in-subset index
        let mut subset_seed = [0u8; 16];
        prover_state.fill_challenge_bytes(&mut subset_seed)?;
        let subset_indices = self.map_subset_seed(subset_seed);

        // prover response: for k in S, shift poly; for s not in S, open by revealing r_k
        let (subset_members, subset_non_members) =
            partition_refs(&dealings, &seeds, &subset_indices);
        for dealing in subset_members {
            let shifted_poly: DensePolynomial<C::ScalarField> = &dealing.0 + &poly;
            // omega''_k in paper
            prover_state.add_scalars(&shifted_poly.coeffs)?;

            // v_k in paper
            prover_state.add_points(&[dealing.2.epk.into_group()])?;
            // e_k1, .., e_kn in paper
            for ct in dealing.2.cts.iter() {
                prover_state.add_bytes(ct)?;
            }
        }
        for seed in subset_non_members {
            prover_state.add_bytes(seed)?;
        }

        Ok((
            VessCiphertext {
                transcript: prover_state.narg_string().to_vec(),
            },
            comm,
        ))
    }

    /// Verify if the ciphertext (for all recipients) correctly encrypting valid secret shares,
    /// verifiable by anyone.
    pub fn verify(
        &self,
        _ct: &VessCiphertext,
        _comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
    ) -> Result<bool, VessError> {
        todo!("to be implemented in phase 2")
    }

    /// Decrypt as the `node_idx`-th receiver with decryption key `recv_sk`
    pub fn decrypt_share(
        &self,
        node_idx: usize,
        recv_sk: &C::ScalarField,
        ct: &VessCiphertext,
        aad: &[u8],
    ) -> Result<C::ScalarField, VessError> {
        // let n = self.vss_pp.n.get() as usize;
        // let recv_ct = ct
        //     .mre_ct
        //     .get_recipient_ct(node_idx)
        //     .ok_or(VessError::IndexOutOfBound(n, node_idx))?;

        // let pt = mre::decrypt::<C, sha2::Sha256>(node_idx, recv_sk, &recv_ct, aad)?;
        // let share: C::ScalarField = CanonicalDeserialize::deserialize_compressed(&*pt)?;

        // Ok(share)
        todo!()
    }
}

/// Returns the `idx`-th combinations in all "n chooses k" lexicologically ordered subsets.
/// The returned subsets are k indices in the set {0,.., n-1}.
/// See doc of [`ShoupVess::map_subset_seed()`] for pseudocode for this algorithm.
fn unrank_combinations(mut n: u128, mut k: u128, mut idx: u128) -> Vec<usize> {
    let subset_size = k as usize;
    let mut cur = 0usize;
    let mut subset_indices = vec![];
    if k == 0 || n < k {
        return subset_indices;
    }

    let mut cnk1 = binomial(n - 1, k - 1);
    // C(n, k) = C(n-1, k-1) * n / k
    let mut cnk = cnk1 * n / k;

    while k > 0 {
        if idx < cnk1 {
            // decrement both n and k, thus cnk' = binom(n-1, k-1)
            cnk = cnk1;
            // cnk1' = binom(n-2, k-2) = binom(n-1, k-1) * (k-1) / (n-1)
            cnk1 = if n > 1 {
                cnk1 * (k - 1) / (n - 1)
            } else {
                1 // terminal case: binom(0,0) = 1
            };

            // include cur in the subset
            subset_indices.push(cur);
            k -= 1;
        } else {
            // exclude cur in the subset
            idx -= cnk1;

            // only decrement n, thus cnk' = binom(n-1, k) = binom(n,k) - binom(n-1, k-1)
            cnk = cnk - cnk1;
            // cnk1' = binom(n-2, k-1) = binom(n-1, k-1) * (n-k) / (n-1)
            cnk1 = if n > 1 {
                cnk1 * (n - k) / (n - 1)
            } else {
                0 // binom(0, k-1) = 0 when n == 0
            };
        }
        n -= 1;
        cur += 1;
    }

    debug_assert_eq!(subset_indices.len(), subset_size);
    subset_indices
}

/// Given two vectors of the same length n, and a subset (represented by indices \in {0, .., n-1}),
/// return two vectors of refs, first comes from v1 with index selected by `subset_indices`,
/// second comes from v2 with index not in `subset_indices`
fn partition_refs<'t, 'u, T, U>(
    v1: &'t [T],
    v2: &'u [U],
    subset_indices: &[usize],
) -> (Vec<&'t T>, Vec<&'u U>) {
    debug_assert_eq!(v1.len(), v2.len());
    let n = v1.len();
    let subset_size = subset_indices.len();
    let mut selected = Vec::with_capacity(subset_size);
    let mut rest = Vec::with_capacity(n - subset_size);

    let mut subset_iter = subset_indices.iter().copied().peekable();
    let mut next_subset_idx = subset_iter.next();
    for i in 0..n {
        match next_subset_idx {
            Some(j) if i == j => {
                selected.push(&v1[i]);
                next_subset_idx = subset_iter.next();
            }
            _ => rest.push(&v2[i]),
        }
    }

    debug_assert_eq!(selected.len(), subset_size);
    debug_assert_eq!(selected.len() + rest.len(), n);
    (selected, rest)
}

/// Error related to VESS scheme
#[derive(Error, Debug)]
pub enum VessError {
    #[error("mre failed: {0}")]
    Mre(#[from] mre::MultiRecvEncError),
    #[error("transcript err: {0}")]
    Transcript(#[from] spongefish::ProofError),
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

impl From<spongefish::DomainSeparatorMismatch> for VessError {
    fn from(e: spongefish::DomainSeparatorMismatch) -> Self {
        Self::Transcript(spongefish::ProofError::from(e))
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
    use std::{collections::BTreeSet, iter::repeat_with};

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
        let (ct, comm) = vess.encrypted_shares(&recv_pks, secret, aad).unwrap();

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

    #[test]
    fn test_unrank_combinations() {
        let n = 10u128;
        let k = 3u128;
        let num_subsets = binomial(n, k);

        let mut subsets = BTreeSet::new();
        for idx in 0..num_subsets {
            let subset = unrank_combinations(n, k, idx);
            assert_eq!(subset.len(), k as usize, "expect subset of right size");
            let indices = BTreeSet::from_iter(subset.iter());
            assert_eq!(indices.len(), k as usize, "expect no duplicated indices");
            // ensure every subset is unique (has not been inserted before)
            assert!(subsets.insert(subset));
        }
    }
}
