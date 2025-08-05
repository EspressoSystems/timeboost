//! Implementation of Feldman VSS

use ark_ec::CurveGroup;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_serialize::{CanonicalSerialize, SerializationError, serialize_to_vec};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use derive_more::{Deref, From, IntoIterator};
use multisig::Committee;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{iter::successors, num::NonZeroUsize};

use crate::{
    interpolation::{interpolate, interpolate_in_exponent},
    traits::dkg::{KeyResharing, VerifiableSecretSharing, VssError},
};

/// Feldman VSS: <https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf>
#[derive(Debug, Clone)]
pub struct FeldmanVss<C: CurveGroup>(PhantomData<C>);

#[derive(Debug, Clone, Copy)]
pub struct FeldmanVssPublicParam {
    // reconstruction threshold t
    pub t: NonZeroUsize,
    // total number of nodes
    pub n: NonZeroUsize,
}

impl FeldmanVssPublicParam {
    pub fn new(t: NonZeroUsize, n: NonZeroUsize) -> Self {
        Self { t, n }
    }

    pub fn from(c: &Committee) -> Self {
        Self::new(c.one_honest_threshold(), c.size())
    }

    pub fn threshold(&self) -> usize {
        self.t.get()
    }

    pub fn num_nodes(&self) -> usize {
        self.n.get()
    }
}

impl<C: CurveGroup> FeldmanVss<C> {
    /// sample a random polynomial for VSS `secret`, returns the poly and its feldman commitment
    pub(crate) fn rand_poly_and_commit<R: Rng>(
        pp: &FeldmanVssPublicParam,
        secret: C::ScalarField,
        rng: &mut R,
    ) -> (DensePolynomial<C::ScalarField>, FeldmanCommitment<C>) {
        // sample random polynomial of degree t-1 (s.t. any t evaluations can interpolate this poly)
        // f(X) = Sum a_i * X^i
        let mut poly = DensePolynomial::<C::ScalarField>::rand(pp.t.get() - 1, rng);
        // f(0) = a_0 set to the secret, this index access will never panic since t>0
        poly.coeffs[0] = secret;

        // prepare commitment, u = (g^a_0, g^a_1, ..., g^a_t-1)
        let commitment = C::generator().batch_mul(&poly.coeffs);

        (poly, commitment.into())
    }

    /// given a secret-embedded polynomial, compute the Shamir secret shares
    /// node i \in {0,.. ,n-1} get f(i+1)
    pub(crate) fn compute_shares(
        pp: &FeldmanVssPublicParam,
        poly: &DensePolynomial<C::ScalarField>,
    ) -> impl Iterator<Item = C::ScalarField> {
        (0..pp.n.get()).map(|node_idx| poly.evaluate(&((node_idx + 1) as u64).into()))
    }

    /// same as [`Self::compute_shares()`], but output an iterator of bytes
    pub(crate) fn compute_serialized_shares(
        pp: &FeldmanVssPublicParam,
        poly: &DensePolynomial<C::ScalarField>,
    ) -> impl Iterator<Item = Vec<u8>> {
        Self::compute_shares(pp, poly)
            .map(|s| serialize_to_vec![s].expect("ark_serialize valid shares never panic"))
    }

    /// given the Feldman commitment (\vec{u} in paper), compute the `i`-th node's public share,
    /// which is g^alpha_i where alpha_i is `i`-th secret share.
    pub(crate) fn derive_public_share(
        pp: &FeldmanVssPublicParam,
        node_idx: usize,
        commitment: &[C::Affine],
    ) -> Result<C, VssError> {
        let n = pp.n.get();
        let t = pp.t.get();

        // input validation
        if node_idx >= n {
            return Err(VssError::IndexOutOfBound(n - 1, node_idx));
        }
        if commitment.len() != t {
            return Err(VssError::InvalidCommitment);
        }

        let eval_in_exp = Self::derive_public_share_unchecked(node_idx, commitment);
        Ok(eval_in_exp)
    }

    /// Given the Feldman commitment, compute the `i`-th node's public share,
    /// which is g^alpha_i where alpha_i is `i`-th secret share.
    /// We assume `commitment` has the right length (namely `=threshold`) without checks
    pub fn derive_public_share_unchecked(node_idx: usize, commitment: &[C::Affine]) -> C {
        let t = commitment.len();

        // i-th node computes g^f(i+1), namely poly eval in the exponent
        // g^f(x) = Prod_{j \in [0, t-1]} u_j ^ {x^j}
        let eval_point = C::ScalarField::from(node_idx as u64 + 1);
        let powers = successors(Some(C::ScalarField::from(1u64)), |prev| {
            Some(*prev * eval_point)
        })
        .take(t)
        .collect::<Vec<_>>();

        // infalliable
        C::msm(commitment, &powers).expect("bases and scalars shouuld have the same length")
    }
}

impl<C: CurveGroup> VerifiableSecretSharing for FeldmanVss<C> {
    type PublicParam = FeldmanVssPublicParam;
    type Secret = C::ScalarField;
    type SecretShare = C::ScalarField;
    type Commitment = FeldmanCommitment<C>;

    fn share<R: Rng>(
        pp: &Self::PublicParam,
        rng: &mut R,
        secret: Self::Secret,
    ) -> (Vec<Self::SecretShare>, Self::Commitment) {
        let (poly, comm) = Self::rand_poly_and_commit(pp, secret, rng);
        let shares = Self::compute_shares(pp, &poly).collect();
        (shares, comm)
    }

    fn verify(
        pp: &Self::PublicParam,
        node_idx: usize,
        share: &Self::SecretShare,
        commitment: &Self::Commitment,
    ) -> Result<(), VssError> {
        let public_share = Self::derive_public_share(pp, node_idx, commitment)?;
        if C::generator().mul(share) == public_share {
            Ok(())
        } else {
            Err(VssError::FailedVerification)
        }
    }

    fn reconstruct(
        pp: &Self::PublicParam,
        shares: impl Iterator<Item = (usize, Self::SecretShare)>,
    ) -> Result<Self::Secret, VssError> {
        let shares = shares.collect::<Vec<_>>();
        let n = pp.n.get();
        let t = pp.t.get();
        // input validation
        if shares.len() != t {
            return Err(VssError::MismatchedSharesCount(t, shares.len()));
        }
        for (idx, _) in shares.iter() {
            if *idx >= n {
                return Err(VssError::IndexOutOfBound(n - 1, *idx));
            }
        }

        // Lagrange interpolate to get back the secret
        let eval_points: Vec<_> = shares
            .iter()
            .map(|&(idx, _)| C::ScalarField::from(idx as u64 + 1))
            .collect();
        let evals: Vec<_> = shares.iter().map(|&(_, share)| share).collect();
        interpolate::<C>(&eval_points, &evals)
            .map_err(|e| VssError::FailedReconstruction(e.to_string()))
    }
}

/// Commitment of a dealing in Feldman VSS
#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    From,
    Deref,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    IntoIterator,
)]
pub struct FeldmanCommitment<C: CurveGroup> {
    #[serde_as(as = "crate::SerdeAs")]
    comm: Vec<C::Affine>,
}

impl<C: CurveGroup> FeldmanCommitment<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("serializing feldman commitment")
    }

    pub fn try_from_bytes<const N: usize>(value: &[u8]) -> Result<Self, SerializationError> {
        crate::try_from_bytes::<Self, N>(value)
    }
    pub fn try_from_str<const N: usize>(value: &str) -> Result<Self, SerializationError> {
        crate::try_from_str::<Self, N>(value)
    }
}

impl<C: CurveGroup> KeyResharing<Self> for FeldmanVss<C> {
    fn reshare<R: Rng>(
        new_pp: &FeldmanVssPublicParam,
        old_share: &C::ScalarField,
        rng: &mut R,
    ) -> (Vec<C::ScalarField>, FeldmanCommitment<C>) {
        let (poly, comm) = Self::rand_poly_and_commit(new_pp, *old_share, rng);
        let reshares = Self::compute_shares(new_pp, &poly).collect();
        (reshares, comm)
    }

    fn verify_reshare(
        old_pp: &FeldmanVssPublicParam,
        new_pp: &FeldmanVssPublicParam,
        send_node_idx: usize,
        recv_node_idx: usize,
        old_commitment: &FeldmanCommitment<C>,
        row_commitment: &FeldmanCommitment<C>,
        reshare: &C::ScalarField,
    ) -> Result<(), VssError> {
        let old_public_share = Self::derive_public_share(old_pp, send_node_idx, old_commitment)?;
        let new_public_share = Self::derive_public_share(new_pp, recv_node_idx, row_commitment)?;

        if C::generator().mul(reshare) == new_public_share
            && row_commitment[0] == old_public_share.into_affine()
        {
            Ok(())
        } else {
            Err(VssError::FailedVerification)
        }
    }

    fn combine(
        old_pp: &FeldmanVssPublicParam,
        new_pp: &FeldmanVssPublicParam,
        send_node_indices: &[usize],
        row_commitments: &[FeldmanCommitment<C>],
        recv_node_idx: usize,
        recv_reshares: &[C::ScalarField],
    ) -> Result<(C::ScalarField, FeldmanCommitment<C>), VssError> {
        // input validation
        let n = old_pp.n.get();
        if send_node_indices.is_empty() || row_commitments.is_empty() || recv_reshares.is_empty() {
            return Err(VssError::EmptyReshare);
        }
        for idx in send_node_indices.iter() {
            if *idx >= n {
                return Err(VssError::IndexOutOfBound(n - 1, *idx));
            }
        }

        let new_n = new_pp.n.get();
        let new_t = new_pp.t.get();
        if recv_node_idx >= new_n {
            return Err(VssError::IndexOutOfBound(new_n - 1, recv_node_idx));
        }
        if row_commitments.iter().any(|cm| cm.len() != new_t) {
            return Err(VssError::InvalidCommitment);
        }

        let subset_size = recv_reshares.len();
        if send_node_indices.len() != subset_size || row_commitments.len() != subset_size {
            return Err(VssError::MismatchedInputLength);
        }

        // interpolate reshares to get new secret share
        let eval_points: Vec<_> = send_node_indices
            .iter()
            .map(|&idx| C::ScalarField::from(idx as u64 + 1))
            .collect();
        let new_secret = interpolate::<C>(&eval_points, recv_reshares)
            .map_err(|e| VssError::FailedCombine(e.to_string()))?;

        // interpolate in the exponent to get new Feldman commitment
        let new_commitment = (0..new_t)
            .into_par_iter()
            .map(|j| {
                let j_th_coeffs: Vec<C::Affine> =
                    row_commitments.iter().map(|row| row[j]).collect();
                interpolate_in_exponent::<C>(&eval_points, &j_th_coeffs)
                    .map_err(|e| VssError::FailedCombine(e.to_string()))
            })
            .collect::<Result<Vec<_>, VssError>>()?;
        let new_commitment = C::normalize_batch(&new_commitment);

        Ok((new_secret, new_commitment.into()))
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Projective};
    use ark_std::{UniformRand, rand::seq::SliceRandom, test_rng};

    use super::*;

    fn test_feldman_vss_helper<C: CurveGroup>() {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let secret = C::ScalarField::rand(rng);
            let n = rng.gen_range(5..20);
            let t = rng.gen_range(2..n);
            let n_usize = n as usize;
            let t_usize = t as usize;

            let n = NonZeroUsize::new(n as usize).unwrap();
            let t = NonZeroUsize::new(t as usize).unwrap();
            let pp = FeldmanVssPublicParam::new(t, n);

            let (shares, commitment) = FeldmanVss::<C>::share(&pp, rng, secret);
            for (node_idx, s) in shares.iter().enumerate() {
                // happy path
                assert!(FeldmanVss::<C>::verify(&pp, node_idx, s, &commitment).is_ok());

                // sad path
                // wrong node_idx should fail
                assert!(FeldmanVss::<C>::verify(&pp, node_idx + 1, s, &commitment).is_err());

                // wrong secret share should fail
                assert!(
                    FeldmanVss::<C>::verify(
                        &pp,
                        node_idx,
                        &C::ScalarField::rand(rng),
                        &commitment,
                    )
                    .is_err()
                );

                // wrong commitment should fail
                let mut bad_comm = commitment.clone();
                bad_comm.comm[1] = C::Affine::default();
                assert!(FeldmanVss::<C>::verify(&pp, node_idx, s, &bad_comm).is_err());

                // incomplete/dropped commitment should fail
                bad_comm.comm.pop();
                assert!(FeldmanVss::<C>::verify(&pp, node_idx, s, &bad_comm).is_err());
            }

            // 1. Randomly select t-share subset and reconstruct (should succeed)
            let mut indices: Vec<_> = (0..n_usize).collect();
            indices.shuffle(rng);
            let t_indices = &indices[..t_usize];
            let rec = FeldmanVss::<C>::reconstruct(&pp, t_indices.iter().map(|&i| (i, shares[i])))
                .unwrap();
            assert_eq!(rec, secret);

            // 2. Remove one from t-share subset (t-1 shares, should fail)
            assert!(
                FeldmanVss::<C>::reconstruct(
                    &pp,
                    t_indices[..t_usize - 1].iter().map(|&i| (i, shares[i]))
                )
                .is_err()
            );

            // 3. Replace one share in t-size subset with a random (invalid) share (should fail)
            let mut bad_shares = t_indices
                .iter()
                .map(|&i| (i, shares[i]))
                .collect::<Vec<_>>();
            // Replace the first share with a random value
            bad_shares[0] = (bad_shares[0].0, C::ScalarField::rand(rng));
            assert_ne!(
                FeldmanVss::<C>::reconstruct(&pp, bad_shares.into_iter()).unwrap(),
                secret
            );
        }
    }

    #[test]
    fn test_feldman_vss() {
        test_feldman_vss_helper::<G1Projective>();
    }

    // Core key resharing workflow
    fn run_reshare_scenario(
        old_t: usize,
        old_n: usize,
        new_t: usize,
        new_n: usize,
        rng: &mut impl Rng,
    ) {
        let old_pp = FeldmanVssPublicParam::new(
            NonZeroUsize::new(old_t).unwrap(),
            NonZeroUsize::new(old_n).unwrap(),
        );
        let new_pp = FeldmanVssPublicParam::new(
            NonZeroUsize::new(new_t).unwrap(),
            NonZeroUsize::new(new_n).unwrap(),
        );

        let secret = Fr::rand(rng);

        let (old_shares, old_commitment) = FeldmanVss::<G1Projective>::share(&old_pp, rng, secret);

        // Verify original shares
        for (node_idx, share) in old_shares.iter().enumerate() {
            assert!(
                FeldmanVss::<G1Projective>::verify(&old_pp, node_idx, share, &old_commitment)
                    .is_ok()
            );
        }

        let mut reshare_matrix = Vec::new();
        let mut row_commitments = Vec::new();

        for old_share in old_shares.iter() {
            let (reshare_row, row_commitment) =
                FeldmanVss::<G1Projective>::reshare(&new_pp, old_share, rng);
            reshare_matrix.push(reshare_row);
            row_commitments.push(row_commitment);
        }

        // Verify reshares
        for i in 0..old_n {
            for j in 0..new_n {
                assert!(
                    FeldmanVss::<G1Projective>::verify_reshare(
                        &old_pp,
                        &new_pp,
                        i,
                        j,
                        &old_commitment,
                        &row_commitments[i],
                        &reshare_matrix[i][j],
                    )
                    .is_ok()
                );
            }
        }

        let mut new_shares = Vec::new();
        let mut new_commitments = Vec::new();

        for j in 0..new_n {
            let recv_reshares: Vec<Fr> = (0..old_t)
                .collect::<Vec<_>>()
                .iter()
                .map(|&i| reshare_matrix[i][j])
                .collect();
            let selected_row_commitments: Vec<FeldmanCommitment<_>> =
                (0..old_t).map(|i| row_commitments[i].clone()).collect();

            let (new_secret_share, new_commitment) = FeldmanVss::<G1Projective>::combine(
                &old_pp,
                &new_pp,
                &(0..old_t).collect::<Vec<_>>(),
                &selected_row_commitments,
                j,
                &recv_reshares,
            )
            .unwrap();

            new_shares.push(new_secret_share);
            new_commitments.push(new_commitment);

            assert!(
                FeldmanVss::<G1Projective>::verify(
                    &new_pp,
                    j,
                    &new_secret_share,
                    &new_commitments[j]
                )
                .is_ok()
            );
        }

        // Reconstruct secret
        let reconstructed_secret = FeldmanVss::<G1Projective>::reconstruct(
            &new_pp,
            (0..new_t).map(|i| (i, new_shares[i])),
        )
        .unwrap();

        assert_eq!(reconstructed_secret, secret);
    }

    // Test success-path for identical (t,n) → (t',n') case
    #[test]
    fn test_key_resharing_identical_params() {
        let rng = &mut test_rng();

        // Run 7 random trials (between 5-10)
        for _ in 0..7 {
            // Generate random (t,n) parameters
            let n = rng.gen_range(5..12);
            let t = rng.gen_range(2..n);
            run_reshare_scenario(t, n, t, n, rng);
        }
    }

    // Test success-path for different (t,n) → (t',n') cases
    #[test]
    fn test_key_resharing_different_threshold_committee_sizes() {
        let rng = &mut test_rng();

        // Run multiple random trials with different parameter combinations
        for _ in 0..10 {
            // Randomly choose (t,n) parameters for the original committee
            let old_n = rng.gen_range(5..15);
            let old_t = rng.gen_range(2..old_n);

            // Randomly choose (t',n') parameters for the new committee with variations
            // Sometimes larger, sometimes smaller than original
            let new_n = match rng.gen_range(0..3) {
                0 => rng.gen_range(5..old_n),  // Smaller committee
                1 => rng.gen_range(old_n..20), // Larger committee
                _ => rng.gen_range(5..20),     // Random size
            };
            let new_t = rng.gen_range(2..new_n);

            run_reshare_scenario(old_t, old_n, new_t, new_n, rng);
        }
    }

    // Test specific edge cases for minimal thresholds and committee size limits
    #[test]
    fn test_edge_case_minimal_thresholds() {
        let rng = &mut test_rng();

        // Edge case scenarios: (t, n) → (t', n')
        let test_cases = vec![
            ((1, 3), (1, 5)), // (t=1, n=3) → (t'=1, n'=5): minimal threshold expanding committee
            ((2, 2), (2, 2)), // (t=2, n=2) → (t'=2, n'=2): minimal committee size (t=n)
            ((1, 2), (1, 3)), // (t=1, n=2) → (t'=1, n'=3): minimal viable committee expanding
            ((1, 4), (1, 2)), // (t=1, n=4) → (t'=1, n'=2): shrinking to minimal viable size
            ((2, 3), (1, 4)), // (t=2, n=3) → (t'=1, n'=4): threshold reduction with expansion
            ((1, 5), (2, 3)), // (t=1, n=5) → (t'=2, n'=3): threshold increase with shrinking
        ];

        for ((old_t, old_n), (new_t, new_n)) in test_cases {
            run_reshare_scenario(old_t, old_n, new_t, new_n, rng);
        }
    }
}
