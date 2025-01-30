use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use nimue::{
    plugins::ark::{
        FieldChallenges, FieldIOPattern, FieldReader, FieldWriter, GroupIOPattern, GroupPublic,
        GroupReader, GroupWriter,
    },
    Arthur, DuplexHash, IOPattern,
};
use std::marker::PhantomData;

use crate::traits::dleq_proof::{DleqProofError, DleqProofScheme};

/// Chaum-Pedersen proof of discrete log equality.
///
/// Given a tuple (g, g_hat, h, h_hat) prove that DLOG_{g}(g_hat) == DLOG_{h}(h_hat).
///
/// Protocol description (Section 5 in [Sigma.pdf](https://www.cs.au.dk/~ivan/Sigma.pdf)) with additional background on sigma protocols.
pub struct ChaumPedersen<C, D>
where
    C: CurveGroup,
    D: DuplexHash,
{
    _group: PhantomData<C>,
    _hash: PhantomData<D>,
}

pub struct CPParameters<C, D>
where
    C: CurveGroup,
    D: DuplexHash,
{
    _hash: PhantomData<D>,
    pub generator: C,
    pub io_pattern: IOPattern<D>,
}

impl<C: CurveGroup, D: DuplexHash> Clone for CPParameters<C, D> {
    fn clone(&self) -> Self {
        Self {
            _hash: PhantomData,
            generator: self.generator,
            io_pattern: self.io_pattern.clone(),
        }
    }
}

impl<C: CurveGroup, D: DuplexHash> CPParameters<C, D> {
    pub fn new(generator: C) -> Self {
        Self {
            _hash: PhantomData,
            generator,
            io_pattern: <IOPattern<D> as ChaumPedersenIOPattern<C>>::new_cp_proof(
                "dleq::chaum-pedersen",
            ),
        }
    }
}

/// Tuple (g, g_hat, h, h_hat)
///
/// subject to proving: DLOG_{g}(g_hat) == DLOG_{h}(h_hat)
#[derive(Clone)]
pub struct DleqTuple<C: CurveGroup>(C, C, C, C);

impl<C: CurveGroup> DleqTuple<C> {
    pub fn new(g: C, g_hat: C, h: C, h_hat: C) -> Self {
        DleqTuple(g, g_hat, h, h_hat)
    }

    pub fn verify_tuple(&self, x: C::ScalarField) -> bool {
        self.0 * x == self.1 && self.2 * x == self.3
    }
}

#[derive(Clone)]
pub struct Proof {
    pub(crate) transcript: Vec<u8>,
}

/// SAFE IO Pattern for the Chaum-Pedersen sigma protocol
/// (see Algorithm 6 in <https://eprint.iacr.org/2023/522.pdf>)
trait ChaumPedersenIOPattern<C: CurveGroup> {
    fn new_cp_proof(domsep: &str) -> Self;
    fn add_cp_statement(self) -> Self;
    fn add_cp_io(self) -> Self;
}

impl<C, D> ChaumPedersenIOPattern<C> for IOPattern<D>
where
    C: CurveGroup,
    D: DuplexHash,
    IOPattern<D>: GroupIOPattern<C> + FieldIOPattern<C::ScalarField>,
{
    fn new_cp_proof(domsep: &str) -> Self {
        IOPattern::new(domsep).add_cp_statement().add_cp_io()
    }

    fn add_cp_statement(self) -> Self {
        self.add_points(4, "dleq tuple").ratchet()
    }

    fn add_cp_io(self) -> Self {
        self.add_points(2, "commitments (a_1, a_2)")
            .challenge_scalars(1, "challenge (e)")
            .add_scalars(1, "response (z)")
    }
}

impl<C: CurveGroup, D: DuplexHash> DleqProofScheme for ChaumPedersen<C, D> {
    type Parameters = CPParameters<C, D>;
    type DleqTuple = DleqTuple<C>;
    type Scalar = C::ScalarField;
    type Proof = Proof;

    fn setup<R: ark_std::rand::Rng>(rng: &mut R) -> Result<Self::Parameters, DleqProofError> {
        let generator: C = C::rand(rng);
        Ok(CPParameters::new(generator))
    }

    fn prove(
        pp: &Self::Parameters,
        tuple: Self::DleqTuple,
        x: &Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError> {
        if !tuple.verify_tuple(*x) {
            return Err(DleqProofError::Internal(anyhow!(
                "unable to generate proof for invalid tuple"
            )));
        }
        let DleqTuple(g, g_hat, h, h_hat) = tuple;
        let mut merlin = pp.io_pattern.to_merlin();
        merlin.public_points(&[g, g_hat, h, h_hat])?;
        merlin.ratchet()?;

        let k: C::ScalarField = C::ScalarField::rand(merlin.rng());
        let a = g * k;
        let a_hat = h * k;
        merlin.add_points(&[a, a_hat])?;

        let [e]: [C::ScalarField; 1] = merlin.challenge_scalars()?;

        let z: C::ScalarField = k + e * x;
        merlin.add_scalars(&[z])?;
        Ok(Proof {
            transcript: merlin.transcript().to_vec(),
        })
    }

    fn verify(
        pp: &Self::Parameters,
        tuple: DleqTuple<C>,
        proof: &Self::Proof,
    ) -> Result<(), DleqProofError>
    where
        for<'a> Arthur<'a, D>:
            GroupReader<C> + FieldReader<C::ScalarField> + FieldChallenges<C::ScalarField>,
    {
        let mut arthur = pp.io_pattern.to_arthur(&proof.transcript);
        let DleqTuple(g, g_hat, h, h_hat) = tuple;
        arthur.public_points(&[g, g_hat, h, h_hat])?;
        arthur.ratchet()?;

        let [a, a_hat] = arthur.next_points()?;
        let [e] = arthur.challenge_scalars()?;
        let [z] = arthur.next_scalars()?;
        if g * z == a + g_hat * e && h * z == a_hat + h_hat * e {
            Ok(())
        } else {
            Err(DleqProofError::ProofNotValid)
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_std::rand::Rng;
    use ark_std::{test_rng, UniformRand};
    use nimue::{
        hash::Keccak,
        plugins::ark::{FieldChallenges, FieldWriter, GroupPublic, GroupWriter},
        Merlin,
    };

    use crate::{
        cp_proof::{ChaumPedersen, DleqTuple, Proof},
        traits::dleq_proof::DleqProofScheme,
    };

    use super::CPParameters;

    type G = ark_secp256k1::Projective;
    type D = Keccak;
    type S = <ark_secp256k1::Projective as PrimeGroup>::ScalarField;

    #[test]
    fn proof_correctness() {
        let mut rng = test_rng();

        // Setup
        let (params, x, tuple) = setup(&mut rng);

        // Create proof
        let proof = ChaumPedersen::<G, D>::prove(&params, tuple.clone(), &x).unwrap();

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(&params, tuple, &proof);
        assert!(result.is_ok(), "Proof verification failed");
    }

    #[test]
    fn generate_proof_invalid_tuple() {
        let mut rng = test_rng();

        // Setup
        let (params, x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, _) = tuple;
        let y = S::from(2);

        // Generate invalid tuple (g, g_hat, h, h_hat)
        let tuple = DleqTuple::new(g, g_hat, h, h * y);

        // Verify proof
        let proof = ChaumPedersen::<G, D>::prove(&params, tuple.clone(), &x);
        assert!(
            proof.is_err(),
            "Proof generation should fail with invalid tuple"
        );
    }

    #[test]
    fn verify_proof_for_invalid_tuple() {
        let mut rng = test_rng();

        let (params, x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, _) = tuple;

        // Create proof
        let proof = ChaumPedersen::<G, D>::prove(&params, tuple.clone(), &x).unwrap();

        let y = S::rand(&mut rng);
        let tuple_invalid = DleqTuple::new(g, g_hat, h, h * y);
        assert!(!tuple_invalid.verify_tuple(x));
        assert!(!tuple_invalid.verify_tuple(y));

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(&params, tuple_invalid, &proof);
        assert!(
            result.is_err(),
            "Proof verification should fail with invalid tuple"
        );
    }

    #[test]
    fn verify_invalid_proof_for_tuple() {
        let mut rng = test_rng();

        let (params, x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, h_hat) = tuple;

        // Create invalid transcript
        let mut mordred: Merlin<D> = params.io_pattern.to_merlin();
        mordred.public_points(&[g, g_hat, h, h_hat]).unwrap();
        mordred.ratchet().unwrap();

        let k = S::rand(mordred.rng());
        let a = g * k;
        let a_hat = h; // does not commit to `k`
        mordred.add_points(&[a, a_hat]).unwrap();

        let [e]: [S; 1] = mordred.challenge_scalars().unwrap();

        let z = k + e * x;
        mordred.add_scalars(&[z]).unwrap();

        let mordred_proof = Proof {
            transcript: mordred.transcript().to_vec(),
        };

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(&params, tuple, &mordred_proof);
        assert!(
            result.is_err(),
            "Proof verification should fail with invalid transcript"
        );
    }

    fn setup<R: Rng>(mut rng: R) -> (CPParameters<G, D>, S, DleqTuple<G>) {
        // Setup parameters
        let params = ChaumPedersen::<G, D>::setup(&mut rng).unwrap();

        // Generate random scalar x
        let x = S::rand(&mut rng);

        // Generate tuple (g, g_hat, h, h_hat)
        let g = params.generator;
        let g_hat = g * x;
        let h = ark_secp256k1::Projective::rand(&mut rng);
        let h_hat = h * x;
        let tuple = DleqTuple::new(g, g_hat, h, h_hat);
        (params, x, tuple)
    }
}
