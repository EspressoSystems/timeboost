//! Verifiable Encrypted Secret Sharing (VESS) schemes
#![allow(clippy::type_complexity)]
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_serialize::{CanonicalDeserialize, serialize_to_vec};
use ark_std::{
    UniformRand,
    marker::PhantomData,
    rand::{Rng, SeedableRng},
};
use num_integer::{binomial, gcd};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::Digest;
use spongefish::{
    ByteReader, ByteWriter, DefaultHash, UnitToBytes, VerifierState,
    codecs::arkworks_algebra::{
        DeserializeField, DeserializeGroup, FieldDomainSeparator, FieldToUnit,
        GroupDomainSeparator, GroupToUnit,
    },
};
use std::{collections::VecDeque, num::NonZeroU32};
use thiserror::Error;

use crate::{
    feldman::{FeldmanVss, FeldmanVssPublicParam},
    mre::{self, LabeledDecryptionKey, MultiRecvCiphertext},
    traits::dkg::{VerifiableSecretSharing, VssError},
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
        debug_assert_eq!(subset.len(), self.subset_size);
        subset
    }

    /// append `aad` with index value `ith`, returns aad' = aad | ith
    fn indexed_aad(&self, aad: &[u8], ith: usize) -> Vec<u8> {
        let sample_idx = if self.num_repetition < u8::MAX as usize {
            (ith as u8).to_be_bytes().to_vec()
        } else {
            ith.to_be_bytes().to_vec()
        };
        [aad, sample_idx.as_ref()].concat()
    }

    // deterministically generate the `i`-th dealing from a random seed
    // each dealing contains (Shamir poly + Feldman commitment + MRE ciphertext)
    fn new_dealing(
        &self,
        ith: usize,
        seed: &[u8; 32],
        recipients: &[mre::EncryptionKey<C>],
        aad: &[u8],
    ) -> Result<
        (
            DensePolynomial<C::ScalarField>,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
            MultiRecvCiphertext<C, sha2::Sha256>,
        ),
        VessError,
    > {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let vss_secret = C::ScalarField::rand(&mut rng);

        let (poly, comm) =
            FeldmanVss::<C>::rand_poly_and_commit(&self.vss_pp, vss_secret, &mut rng);
        let serialized_shares: Vec<Vec<u8>> =
            FeldmanVss::<C>::compute_serialized_shares(&self.vss_pp, &poly).collect();

        let mre_ct = mre::encrypt::<C, sha2::Sha256, _>(
            recipients,
            &serialized_shares,
            &self.indexed_aad(aad, ith),
            &mut rng,
        )?;
        Ok((poly, comm, mre_ct))
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
        recipients: &[mre::EncryptionKey<C>],
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

        // prepare N random dealings
        let dealings: Vec<(
            DensePolynomial<C::ScalarField>,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
            MultiRecvCiphertext<C, sha2::Sha256>,
        )> = seeds
            .par_iter()
            .enumerate()
            .map(|(i, r)| self.new_dealing(i, r, recipients, aad))
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

    // Verifier's logic until step 4.b (exclusive), shared between `verify()` and `decrypt()`.
    fn verify_internal(
        &self,
        verifier_state: &mut VerifierState,
    ) -> Result<ProverMessageUntilStep4b<C>, VessError> {
        let t = self.vss_pp.t.get() as usize;
        let n = self.vss_pp.n.get() as usize;

        // read C and h from transcript
        let mut expected_comm = vec![C::default(); t];
        verifier_state.fill_next_points(&mut expected_comm)?;
        let comm = C::normalize_batch(&expected_comm);
        let h: [u8; 32] = verifier_state.next_bytes()?;

        // derive the challenge as the subset seed
        let mut subset_seed = [0u8; 16];
        verifier_state.fill_challenge_bytes(&mut subset_seed)?;

        // parse out prover's in-Subset responses (shifted polys and their MRE ciphertexts)
        let mut shifted_polys = VecDeque::new();
        let mut mre_cts: VecDeque<MultiRecvCiphertext<C>> = VecDeque::new();
        for _ in 0..self.subset_size {
            let mut coeffs = vec![C::ScalarField::default(); t];
            verifier_state.fill_next_scalars(&mut coeffs)?;
            shifted_polys.push_back(coeffs);

            let epk: [C; 1] = verifier_state.next_points()?;
            let epk = epk[0].into_affine();

            let mut cts = vec![];
            for _ in 0..n {
                let ct: [u8; 32] = verifier_state.next_bytes()?;
                cts.push(digest::Output::<sha2::Sha256>::from(ct));
            }
            mre_cts.push_back(MultiRecvCiphertext { epk, cts });
        }
        Ok((comm, h, subset_seed, shifted_polys, mre_cts))
    }

    /// Verify if the ciphertext (for all recipients) correctly encrypting valid secret shares,
    /// verifiable by anyone.
    pub fn verify(
        &self,
        recipients: &[mre::EncryptionKey<C>],
        ct: &VessCiphertext,
        comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        aad: &[u8],
    ) -> Result<bool, VessError> {
        let mut verifier_state = self.io_pattern(aad).to_verifier_state(&ct.transcript);

        // verifier logic until Step 4b
        let (expected_comm, h, subset_seed, mut shifted_polys, mut mre_cts) =
            self.verify_internal(&mut verifier_state)?;
        if &expected_comm != comm {
            return Err(VessError::WrongCommitment);
        }

        // parse out prover's response for k notin S
        let mut seeds = VecDeque::new();
        for _ in self.subset_size..self.num_repetition {
            let seed: [u8; 32] = verifier_state.next_bytes()?;
            seeds.push_back(seed);
        }

        // recompute the hash of all the dealings,
        let mut hasher = sha2::Sha256::new();
        hasher.update(aad);

        // k in S, then homomorphically shift commitment; k notin S, reproduce dealing from seed
        let subset_indices = self.map_subset_seed(subset_seed);
        let mut subset_iter = subset_indices.iter().peekable();
        let mut next_subset_idx = subset_iter.next();
        for i in 0..self.num_repetition {
            match next_subset_idx {
                Some(j) if i == *j => {
                    // k in S, shift the commitment
                    let shifted_comm = C::generator().batch_mul(
                        shifted_polys
                            .pop_front()
                            .expect("subset_size > 0, so is shifted_polys.len()")
                            .as_ref(),
                    );
                    for (shifted, delta) in shifted_comm.into_iter().zip(comm.iter()) {
                        // g^omega'' / C in paper
                        hasher.update(serialize_to_vec![shifted - delta]?)
                    }

                    let mre_ct = mre_cts
                        .pop_front()
                        .expect("subset_size > 0, so is mre_cts.len()");
                    hasher.update(mre_ct.to_bytes());

                    next_subset_idx = subset_iter.next();
                }
                _ => {
                    // k notin S, reproduce the dealing deterministically from seed
                    let seed = seeds
                        .pop_front()
                        .expect("subset_size < num_repetitions, so seeds.len() > 0");
                    let (_poly, cm, mre_ct) = self.new_dealing(i, &seed, recipients, aad)?;

                    hasher.update(serialize_to_vec![cm]?);
                    hasher.update(mre_ct.to_bytes());
                }
            }
        }
        debug_assert!(shifted_polys.is_empty());
        debug_assert!(mre_cts.is_empty());
        debug_assert!(seeds.is_empty());

        Ok(h != hasher.finalize().as_slice())
    }

    /// Decrypt with a decryption key `recv_sk` (labeled with node_idx, see `LabeledDecryptionKey`)
    pub fn decrypt_share(
        &self,
        recv_sk: &LabeledDecryptionKey<C>,
        ct: &VessCiphertext,
        aad: &[u8],
    ) -> Result<C::ScalarField, VessError> {
        let n = self.vss_pp.n.get() as usize;
        let node_idx = recv_sk.node_idx;
        let mut verifier_state = self.io_pattern(aad).to_verifier_state(&ct.transcript);

        // verifier logic until Step 4b
        let (comm, _h, subset_seed, shifted_polys, mre_cts) =
            self.verify_internal(&mut verifier_state)?;
        let subset_indices = self.map_subset_seed(subset_seed);
        debug_assert_eq!(subset_indices.len(), shifted_polys.len());

        for ((shifted_coeffs, mre_ct), ith) in
            shifted_polys.iter().zip(mre_cts.iter()).zip(subset_indices)
        {
            let recv_ct = mre_ct
                .get_recipient_ct(node_idx)
                .ok_or(VessError::IndexOutOfBound(n, node_idx))?;
            let pt = recv_sk.decrypt(&recv_ct, &self.indexed_aad(aad, ith))?;
            // mu'_kj in paper
            let unshifted_eval: C::ScalarField =
                CanonicalDeserialize::deserialize_compressed(&*pt)?;

            let shifted_poly = DensePolynomial::from_coefficients_slice(shifted_coeffs);
            let shifted_eval = shifted_poly.evaluate(&C::ScalarField::from(node_idx as u64 + 1));

            // mu_kj in paper
            let share = shifted_eval - unshifted_eval;

            // check correctness
            if FeldmanVss::<C>::verify(&self.vss_pp, node_idx, &share, &comm)? {
                return Ok(share);
            }
        }
        Err(VessError::DecryptionFailed)
    }
}

/// (C, h, s, { rho_k.shifted_poly }_{k in S}, { rho_k.mre_ciphertext }_{k in S})
/// where C is Feldman commitment, h is output of H_compress of all dealings,
/// s is subset seed, S is the corresponding subset
/// shifted_poly is omega''_k in paper
#[allow(type_alias_bounds)]
type ProverMessageUntilStep4b<C: CurveGroup> = (
    Vec<C::Affine>,
    [u8; 32],
    [u8; 16],
    VecDeque<Vec<C::ScalarField>>,
    VecDeque<MultiRecvCiphertext<C>>,
);

// returns x * a / b without overflow panic, assuming the result < u128::MAX
fn overflow_safe_mul_then_div(x: u128, a: u128, b: u128) -> u128 {
    debug_assert!(b != 0);
    if a == 0 {
        return 0;
    }
    if a == b {
        return x;
    }

    // Reduce the fraction a/b to lowest terms
    let g = gcd(a, b);
    let a_reduced = a / g;
    let b_reduced = b / g;

    // To avoid overflow and precision loss, try to divide x by b_reduced first
    let g2 = gcd(x, b_reduced);
    let x_reduced = x / g2;
    let b_final = b_reduced / g2;

    // Now compute x_reduced * a_reduced / b_final
    // Check for potential overflow in multiplication
    if a_reduced <= u128::MAX / x_reduced {
        (x_reduced * a_reduced) / b_final
    } else {
        (x_reduced / b_final) * a_reduced
    }
}

/// Returns the `idx`-th combination in all "n choose k" lexicographically ordered subsets.
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
    // we never use cnk, only cache its value for easier cnk1 derivation
    let mut _cnk = overflow_safe_mul_then_div(cnk1, n, k);

    while k > 0 {
        // Safety check: if we have exhausted all positions but still need to select more elements,
        // something is wrong with the algorithm state or input
        if n == 0 {
            break;
        }

        if idx < cnk1 {
            // decrement both n and k, thus cnk' = binom(n-1, k-1)
            _cnk = cnk1;
            // cnk1' = binom(n-2, k-2) = binom(n-1, k-1) * (k-1) / (n-1)
            cnk1 = if n > 1 && k > 1 {
                overflow_safe_mul_then_div(cnk1, k - 1, n - 1)
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
            if _cnk >= cnk1 {
                _cnk -= cnk1;
            } else {
                _cnk = 0;
            }
            // cnk1' = binom(n-2, k-1) = binom(n-1, k-1) * (n-k) / (n-1)
            cnk1 = if n > k && n > 1 {
                overflow_safe_mul_then_div(cnk1, n - k, n - 1)
            } else {
                0 // when n-1 = k-1, then all future indices should be selected
            };
        }

        n -= 1;
        cur += 1;

        // If we can't select enough elements from remaining positions, select all remaining
        if n == k {
            // Select all remaining positions
            for _ in 0..k {
                subset_indices.push(cur);
                cur += 1;
            }
            break;
        }
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
    #[error("feldman vss err: {0}")]
    Vss(#[from] VssError),
    #[error("serde err: {0}")]
    SerdeError(String),
    #[error("num of recipients, expect: {0}, got: {1}")]
    WrongRecipientsLength(usize, usize),
    #[error("max length: {0}, access index: {1}")]
    IndexOutOfBound(usize, usize),
    #[error("wrong vss commitment supplied")]
    WrongCommitment,
    #[error("decryption fail")]
    DecryptionFailed,
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
    use ark_bls12_381::{Fr, G1Projective};
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

        let recv_sks: Vec<mre::DecryptionKey<G1Projective>> =
            repeat_with(|| mre::DecryptionKey::rand(rng))
                .take(n)
                .collect();
        let recv_pks: Vec<mre::EncryptionKey<G1Projective>> =
            recv_sks.iter().map(mre::EncryptionKey::from).collect();
        let labeled_sks: Vec<LabeledDecryptionKey<G1Projective>> = recv_sks
            .into_iter()
            .enumerate()
            .map(|(i, sk)| sk.label(i))
            .collect();

        let aad = b"Associated data";
        let (ct, comm) = vess.encrypted_shares(&recv_pks, secret, aad).unwrap();

        assert!(vess.verify(&recv_pks, &ct, &comm, aad).unwrap());
        for labeled_recv_sk in labeled_sks {
            let share = vess.decrypt_share(&labeled_recv_sk, &ct, aad).unwrap();
            assert!(Vss::verify(&vess.vss_pp, labeled_recv_sk.node_idx, &share, &comm).unwrap());
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
