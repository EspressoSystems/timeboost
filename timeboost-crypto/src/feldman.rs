//! Implementation of Feldman VSS

use ark_ec::CurveGroup;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_serialize::{CanonicalSerialize, SerializationError, serialize_to_vec};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use derive_more::{Deref, From, IntoIterator};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{iter::successors, num::NonZeroUsize};

use crate::{
    interpolation::interpolate,
    traits::dkg::{VerifiableSecretSharing, VssError},
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

        C::msm(commitment, &powers).expect("infallible: commitment and powers has diff lengths")
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
}
