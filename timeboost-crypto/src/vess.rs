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
use multisig::Committee;
use num_integer::{binomial, gcd};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use spongefish::{
    ByteReader, ByteWriter, DefaultHash, UnitToBytes, VerifierState,
    codecs::arkworks_algebra::{
        DeserializeField, DeserializeGroup, FieldDomainSeparator, FieldToUnit,
        GroupDomainSeparator, GroupToUnit,
    },
};
use std::collections::VecDeque;
use thiserror::Error;

use crate::{
    feldman::{FeldmanCommitment, FeldmanVss, FeldmanVssPublicParam},
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
pub struct ShoupVess<C>
where
    C: CurveGroup,
{
    /// repetition param, N in paper
    num_repetition: usize,
    /// verifier "open" subset S, M=|S| in paper
    subset_size: usize,
    _group: PhantomData<C>,
}

/// Ciphertext of [`ShoupVess`] scheme, verifiable by itself as its constructed as a sigma proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VessCiphertext {
    /// Sigma proof transcript (which contains encrypted MRE ciphertexts to be decrypted)
    transcript: Vec<u8>,
}

impl VessCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.transcript
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.transcript.clone()
    }
}

// First-time DKG or second-time onwards key resharing
enum Mode<C: CurveGroup> {
    Dkg,
    /// the public share of the sender party, see [`FeldmanVss::derive_public_share()`]
    Resharing(C),
}

impl<C: CurveGroup> ShoupVess<C> {
    /// init with system parameters corresponding to a faster variant with larger dealing
    ///
    /// # 127+ bit security instead of strictly =128 bit
    /// parameter different from paper, see rationale in [`Self::map_subset_seed()`]
    pub fn new_fast() -> Self {
        Self {
            num_repetition: 132,
            subset_size: 60,
            _group: PhantomData,
        }
    }

    /// init with system parameters corresponding to a slower variant with shorter dealing
    ///
    /// # 127+ bit security instead of strictly =128 bit
    /// parameter different from paper, see rationale in [`Self::map_subset_seed()`]
    pub fn new_short() -> Self {
        Self {
            num_repetition: 245,
            subset_size: 30,
            _group: PhantomData,
        }
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
    pub fn encrypt_shares<'a, I>(
        &self,
        committee: &Committee,
        recipients: I,
        secret: C::ScalarField,
        aad: &[u8],
    ) -> Result<
        (
            VessCiphertext,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        ),
        VessError,
    >
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>>,
        I::IntoIter: ExactSizeIterator + Clone + Sync,
    {
        self.encrypt_internal(committee, recipients, secret, aad, Mode::Dkg)
    }

    /// Encrypt secret reshares from `KeyResharing::reshare()` with publicly verifiable proof.
    /// See [`Self::encrypt_shares()`] for more documentation.
    pub fn encrypt_reshares<'a, I>(
        &self,
        new_committee: &Committee,
        new_recipients: I,
        old_secret: C::ScalarField,
        aad: &[u8],
    ) -> Result<
        (
            VessCiphertext,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        ),
        VessError,
    >
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>>,
        I::IntoIter: ExactSizeIterator + Clone + Sync,
    {
        let pk = C::generator().mul(&old_secret);
        self.encrypt_internal(
            new_committee,
            new_recipients,
            old_secret,
            aad,
            Mode::Resharing(pk),
        )
    }

    /// Verify if the ciphertext (for all recipients) correctly encrypting valid secret shares,
    /// verifiable by anyone.
    pub fn verify_shares<'a, I>(
        &self,
        committee: &Committee,
        recipients: I,
        ct: &VessCiphertext,
        comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        aad: &[u8],
    ) -> Result<(), VessError>
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>> + Clone,
        I::IntoIter: ExactSizeIterator,
    {
        self.verify_internal(committee, recipients, ct, comm, aad, Mode::Dkg)
    }

    /// Verify the encrypted reshares from `pub_share` (see [`FeldmanVss::derive_public_share()`]),
    /// The `pub_share` can be directly extracted from `i`-th index in CombKey.
    pub fn verify_reshares<'a, I>(
        &self,
        new_committee: &Committee,
        new_recipients: I,
        ct: &VessCiphertext,
        comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        aad: &[u8],
        pub_share: C,
    ) -> Result<(), VessError>
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>> + Clone,
        I::IntoIter: ExactSizeIterator,
    {
        self.verify_internal(
            new_committee,
            new_recipients,
            ct,
            comm,
            aad,
            Mode::Resharing(pub_share),
        )
    }

    /// Decrypt with a decryption key `recv_sk` (labeled with node_idx, see `LabeledDecryptionKey`)
    pub fn decrypt_share(
        &self,
        committee: &Committee,
        recv_sk: &LabeledDecryptionKey<C>,
        ct: &VessCiphertext,
        aad: &[u8],
    ) -> Result<C::ScalarField, VessError> {
        self.decrypt_internal(committee, recv_sk, ct, aad, Mode::Dkg)
    }

    /// Decrypt the reshares from member in the previous committee with
    /// `pub_share` (see [`FeldmanVss::derive_public_share()`]).
    /// The `pub_share` can be directly extracted from `i`-th index in CombKey.
    /// `committee` is the current committee (or equivalently `new_committee` in encrypt_reshares())
    pub fn decrypt_reshare(
        &self,
        committee: &Committee,
        recv_sk: &LabeledDecryptionKey<C>,
        ct: &VessCiphertext,
        aad: &[u8],
        pub_share: C,
    ) -> Result<C::ScalarField, VessError> {
        self.decrypt_internal(committee, recv_sk, ct, aad, Mode::Resharing(pub_share))
    }
}

impl<C: CurveGroup> ShoupVess<C> {
    /// construct the transcript pattern in the interactive proof for Fiat-Shamir transformation.
    /// `aad`: associated data for context/session identifier
    /// IOPattern binds all public parameters including N, M, t, n, aad, to avoid weak FS attack.
    fn io_pattern(
        &self,
        vss_pp: &FeldmanVssPublicParam,
        aad: &[u8],
        mode: &Mode<C>,
    ) -> spongefish::DomainSeparator {
        let t = vss_pp.t.get();
        let n = vss_pp.n.get();

        let mut ds = spongefish::DomainSeparator::<DefaultHash>::new(&format!(
            "vess-ad-{}",
            bs58::encode(aad).into_string()
        ));

        // for resharing, the transcript is bound to the public share (g^alpha_i) of the sender,
        // to ensure the reshares are computed from valid original secrets.
        if matches!(mode, Mode::Resharing(_)) {
            ds = GroupDomainSeparator::<C>::add_points(ds, 1, "pk");
        }

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
    fn new_dealing<'a, I>(
        &self,
        vss_pp: &FeldmanVssPublicParam,
        ith: usize,
        seed: &[u8; 32],
        recipients: I,
        aad: &[u8],
    ) -> Result<
        (
            DensePolynomial<C::ScalarField>,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
            MultiRecvCiphertext<C, sha2::Sha256>,
        ),
        VessError,
    >
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>>,
        I::IntoIter: ExactSizeIterator,
    {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let vss_secret = C::ScalarField::rand(&mut rng);

        let (poly, comm) = FeldmanVss::<C>::rand_poly_and_commit(vss_pp, vss_secret, &mut rng);
        let serialized_shares: Vec<Vec<u8>> =
            FeldmanVss::<C>::compute_serialized_shares(vss_pp, &poly).collect();

        let mre_ct = mre::encrypt::<C, sha2::Sha256, _, _>(
            recipients,
            &serialized_shares,
            &self.indexed_aad(aad, ith),
            &mut rng,
        )?;
        Ok((poly, comm, mre_ct))
    }

    // core logic of encrypting shares, most of which are shared between dkg and resharing
    fn encrypt_internal<'a, I>(
        &self,
        committee: &Committee,
        recipients: I,
        secret: C::ScalarField,
        aad: &[u8],
        mode: Mode<C>,
    ) -> Result<
        (
            VessCiphertext,
            <FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        ),
        VessError,
    >
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>>,
        I::IntoIter: ExactSizeIterator + Clone + Sync,
    {
        // input validation - check length without consuming the iterator
        let recipients_iter = recipients.into_iter();
        let vss_pp = FeldmanVssPublicParam::from(committee);
        let n = vss_pp.num_nodes();
        if recipients_iter.len() != n {
            return Err(VessError::WrongRecipientsLength(n, recipients_iter.len()));
        }

        let mut prover_state = self.io_pattern(&vss_pp, aad, &mode).to_prover_state();

        if let Mode::Resharing(pk) = mode {
            prover_state.add_points(&[pk])?;
        }

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
            .map(|(i, seed)| self.new_dealing(&vss_pp, i, seed, recipients_iter.clone(), aad))
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
            FeldmanVss::<C>::rand_poly_and_commit(&vss_pp, secret, prover_state.rng());

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

    fn verify_internal<'a, I>(
        &self,
        committee: &Committee,
        recipients: I,
        ct: &VessCiphertext,
        comm: &<FeldmanVss<C> as VerifiableSecretSharing>::Commitment,
        aad: &[u8],
        mode: Mode<C>,
    ) -> Result<(), VessError>
    where
        I: IntoIterator<Item = &'a mre::EncryptionKey<C>> + Clone,
        I::IntoIter: ExactSizeIterator,
    {
        let vss_pp = FeldmanVssPublicParam::from(committee);
        let mut verifier_state = self
            .io_pattern(&vss_pp, aad, &mode)
            .to_verifier_state(&ct.transcript);

        // verifier logic until Step 4b
        let (expected_comm, h, subset_seed, mut shifted_polys, mut mre_cts) =
            self.verify_core(&vss_pp, &mut verifier_state, &mode)?;
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

                    let mut unshifted_comm = vec![];
                    for (shifted, delta) in shifted_comm.into_iter().zip(comm.iter()) {
                        // g^omega'' / C in paper
                        unshifted_comm.push(shifted - delta);
                    }
                    let unshifted_comm = C::normalize_batch(&unshifted_comm);
                    hasher.update(serialize_to_vec![unshifted_comm]?);

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
                    let (_poly, cm, mre_ct) =
                        self.new_dealing(&vss_pp, i, &seed, recipients.clone(), aad)?;

                    hasher.update(serialize_to_vec![cm]?);
                    hasher.update(mre_ct.to_bytes());
                }
            }
        }
        debug_assert!(shifted_polys.is_empty());
        debug_assert!(mre_cts.is_empty());
        debug_assert!(seeds.is_empty());

        if h == hasher.finalize().as_slice() {
            Ok(())
        } else {
            Err(VessError::FailedVerification)
        }
    }

    // Verifier's core logic until step 4.b (exclusive), shared between `verify()` and `decrypt()`.
    fn verify_core(
        &self,
        vss_pp: &FeldmanVssPublicParam,
        verifier_state: &mut VerifierState,
        mode: &Mode<C>,
    ) -> Result<ProverMessageUntilStep4b<C>, VessError> {
        let t = vss_pp.t.get();
        let n = vss_pp.n.get();

        // for resharing, we have two extra checks:
        // 1. the transcript is indeed bound to the sender's `public_share`
        // 2. it's a correct reshare, thus commitment[0] = g^alpha = pk
        if let Mode::Resharing(pk) = mode {
            let pk_read: [C; 1] = verifier_state.next_points()?;
            if &pk_read[0] != pk {
                return Err(VessError::WrongSender);
            }
        }

        // read C and h from transcript
        let mut expected_comm = vec![C::default(); t];
        verifier_state.fill_next_points(&mut expected_comm)?;
        if let Mode::Resharing(pk) = mode {
            if expected_comm.first().expect("threshold > 0") != pk {
                return Err(VessError::FailedVerification);
            }
        }

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
        Ok((comm.into(), h, subset_seed, shifted_polys, mre_cts))
    }

    // core logic to decrypt
    fn decrypt_internal(
        &self,
        committee: &Committee,
        recv_sk: &LabeledDecryptionKey<C>,
        ct: &VessCiphertext,
        aad: &[u8],
        mode: Mode<C>,
    ) -> Result<C::ScalarField, VessError> {
        let vss_pp = FeldmanVssPublicParam::from(committee);
        let n = vss_pp.n.get();
        let node_idx = recv_sk.node_idx;
        let mut verifier_state = self
            .io_pattern(&vss_pp, aad, &mode)
            .to_verifier_state(&ct.transcript);

        // verifier logic until Step 4b
        let (comm, _h, subset_seed, shifted_polys, mre_cts) =
            self.verify_core(&vss_pp, &mut verifier_state, &mode)?;
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
            if FeldmanVss::<C>::verify(&vss_pp, node_idx, &share, &comm).is_ok() {
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
    FeldmanCommitment<C>,
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
    #[error("wrong public share or sender node index")]
    WrongSender,
    #[error("failed verification: proof verification failed")]
    FailedVerification,
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        iter::repeat_with,
    };

    type Vss = FeldmanVss<G1Projective>;

    fn test_vess_correctness_helper(vess: ShoupVess<G1Projective>) {
        let rng = &mut StdRng::seed_from_u64(0);
        let secret = Fr::rand(rng);

        // Create a test committee
        let committee_size = 13;
        let keypairs: Vec<multisig::Keypair> = (0..committee_size)
            .map(|_| multisig::Keypair::generate())
            .collect();
        let committee = multisig::Committee::new(
            0u64,
            keypairs
                .iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let n = committee.size().get();

        let recv_sks: Vec<mre::DecryptionKey<G1Projective>> =
            repeat_with(|| mre::DecryptionKey::rand(rng))
                .take(n)
                .collect();
        let recv_pks: BTreeMap<usize, mre::EncryptionKey<G1Projective>> = recv_sks
            .iter()
            .enumerate()
            .map(|(i, sk)| (i, mre::EncryptionKey::from(sk)))
            .collect();
        let labeled_sks: Vec<LabeledDecryptionKey<G1Projective>> = recv_sks
            .into_iter()
            .enumerate()
            .map(|(i, sk)| sk.label(i))
            .collect();

        let aad = b"Associated data";
        let (ct, comm) = vess
            .encrypt_shares(&committee, recv_pks.values(), secret, aad)
            .unwrap();

        assert!(
            vess.verify_shares(&committee, recv_pks.values(), &ct, &comm, aad)
                .is_ok()
        );
        for labeled_recv_sk in labeled_sks {
            let share = vess
                .decrypt_share(&committee, &labeled_recv_sk, &ct, aad)
                .unwrap();
            let vss_pp = FeldmanVssPublicParam::from(&committee);
            assert!(Vss::verify(&vss_pp, labeled_recv_sk.node_idx, &share, &comm).is_ok());
        }
    }

    #[test]
    fn test_vess_correctness() {
        test_vess_correctness_helper(ShoupVess::new_fast());
        test_vess_correctness_helper(ShoupVess::new_short());
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
