//! Implementation of Feldman VSS

use ark_ec::CurveGroup;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use rayon::prelude::*;
use std::{iter::successors, num::NonZeroU32};

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
    pub(crate) t: NonZeroU32,
    // total number of nodes
    pub(crate) n: NonZeroU32,
}

impl FeldmanVssPublicParam {
    pub fn new(t: NonZeroU32, n: NonZeroU32) -> Self {
        Self { t, n }
    }
}

impl<C: CurveGroup> FeldmanVss<C> {
    /// sample a random polynomial for VSS `secret`, returns the poly and its feldman commitment
    pub(crate) fn rand_poly_and_commit<R: Rng>(
        pp: &FeldmanVssPublicParam,
        secret: C::ScalarField,
        rng: &mut R,
    ) -> (DensePolynomial<C::ScalarField>, Vec<C::Affine>) {
        // sample random polynomial of degree t-1 (s.t. any t evaluations can interpolate this poly)
        // f(X) = Sum a_i * X^i
        let mut poly = DensePolynomial::<C::ScalarField>::rand(pp.t.get() as usize - 1, rng);
        // f(0) = a_0 set to the secret, this index access will never panic since t>0
        poly.coeffs[0] = secret;

        // prepare commitment, u = (g^a_0, g^a_1, ..., g^a_t-1)
        let commitment = C::generator().batch_mul(&poly.coeffs);

        (poly, commitment)
    }

    /// given a secret-embedded polynomial, compute the Shamir secret shares
    /// node i \in {0,.. ,n-1} get f(i+1)
    pub(crate) fn compute_shares(
        pp: &FeldmanVssPublicParam,
        poly: &DensePolynomial<C::ScalarField>,
    ) -> impl Iterator<Item = C::ScalarField> {
        (0..pp.n.get()).map(|node_idx| poly.evaluate(&(node_idx + 1).into()))
    }

    /// given the Feldman commitment (\vec{u} in paper), compute the `i`-th node's public share,
    /// which is g^alpha_i where alpha_i is `i`-th secret share.
    pub(crate) fn derive_public_share(
        pp: &FeldmanVssPublicParam,
        node_idx: usize,
        commitment: &[C::Affine],
    ) -> Result<C, VssError> {
        let n = pp.n.get() as usize;
        let t = pp.t.get() as usize;

        // input validation
        if node_idx >= n {
            return Err(VssError::IndexOutOfBound(n - 1, node_idx));
        }
        if commitment.len() != t {
            return Err(VssError::InvalidCommitment);
        }

        // i-th node computes g^f(i+1), namely poly eval in the exponent
        // g^f(x) = Prod_{j \in [0, t-1]} u_j ^ {x^j}
        let eval_point = C::ScalarField::from(node_idx as u64 + 1);
        let powers = successors(Some(C::ScalarField::from(1u64)), |prev| {
            Some(*prev * eval_point)
        })
        .take(t)
        .collect::<Vec<_>>();
        let eval_in_exp = C::msm(commitment, &powers).map_err(|_| {
            VssError::InternalError("commitments and powers mismatched length".to_string())
        })?;

        Ok(eval_in_exp)
    }
}

impl<C: CurveGroup> VerifiableSecretSharing for FeldmanVss<C> {
    type PublicParam = FeldmanVssPublicParam;
    type Secret = C::ScalarField;
    type SecretShare = C::ScalarField;
    type Commitment = Vec<C::Affine>;

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
    ) -> Result<bool, VssError> {
        let public_share = Self::derive_public_share(pp, node_idx, commitment)?;
        Ok(C::generator().mul(share) == public_share)
    }

    fn reconstruct(
        pp: &Self::PublicParam,
        shares: impl Iterator<Item = (usize, Self::SecretShare)>,
    ) -> Result<Self::Secret, VssError> {
        let shares = shares.collect::<Vec<_>>();
        let n = pp.n.get() as usize;
        let t = pp.t.get() as usize;
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

impl<C: CurveGroup> KeyResharing<Self> for FeldmanVss<C> {
    fn reshare<R: Rng>(
        new_pp: &FeldmanVssPublicParam,
        old_share: &C::ScalarField,
        rng: &mut R,
    ) -> (Vec<C::ScalarField>, Vec<C::Affine>) {
        let (poly, comm) = Self::rand_poly_and_commit(new_pp, *old_share, rng);
        let reshares = Self::compute_shares(new_pp, &poly).collect();
        (reshares, comm)
    }

    fn verify_reshare(
        old_pp: &FeldmanVssPublicParam,
        new_pp: &FeldmanVssPublicParam,
        send_node_idx: usize,
        recv_node_idx: usize,
        old_commitment: &Vec<C::Affine>,
        row_commitment: &Vec<C::Affine>,
        reshare: &C::ScalarField,
    ) -> Result<bool, VssError> {
        let old_public_share = Self::derive_public_share(old_pp, send_node_idx, old_commitment)?;
        let new_public_share = Self::derive_public_share(new_pp, recv_node_idx, row_commitment)?;
        Ok(C::generator().mul(reshare) == new_public_share
            && row_commitment[0] == old_public_share.into_affine())
    }

    fn combine(
        old_pp: &FeldmanVssPublicParam,
        new_pp: &FeldmanVssPublicParam,
        send_node_indices: &[usize],
        row_commitments: &[Vec<C::Affine>],
        recv_node_idx: usize,
        recv_reshares: &[C::ScalarField],
    ) -> Result<(C::ScalarField, Vec<C::Affine>), VssError> {
        // input validation
        let n = old_pp.n.get() as usize;
        if send_node_indices.is_empty() || row_commitments.is_empty() || recv_reshares.is_empty() {
            return Err(VssError::EmptyReshare);
        }
        for idx in send_node_indices.iter() {
            if *idx >= n {
                return Err(VssError::IndexOutOfBound(n - 1, *idx));
            }
        }

        let new_n = new_pp.n.get() as usize;
        let new_t = new_pp.t.get() as usize;
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

        Ok((new_secret, new_commitment))
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::G1Projective;
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

            let n = NonZeroU32::new(n).unwrap();
            let t = NonZeroU32::new(t).unwrap();
            let pp = FeldmanVssPublicParam::new(t, n);

            let (shares, commitment) = FeldmanVss::<C>::share(&pp, rng, secret);
            for (node_idx, s) in shares.iter().enumerate() {
                // happy path
                assert!(FeldmanVss::<C>::verify(&pp, node_idx, s, &commitment).unwrap());

                // sad path
                // wrong node_idx should fail
                assert!(
                    !FeldmanVss::<C>::verify(&pp, node_idx + 1, s, &commitment).unwrap_or(false)
                );

                // wrong secret share should fail
                assert!(
                    !FeldmanVss::<C>::verify(
                        &pp,
                        node_idx,
                        &C::ScalarField::rand(rng),
                        &commitment,
                    )
                    .unwrap()
                );

                // wrong commitment should fail
                let mut bad_comm = commitment.clone();
                bad_comm[1] = C::Affine::default();
                assert!(!FeldmanVss::<C>::verify(&pp, node_idx, s, &bad_comm).unwrap());

                // incomplete/dropped commitment should fail
                bad_comm.pop();
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

    #[test]
    fn test_key_resharing() {
        let rng = &mut test_rng();
    }
}
