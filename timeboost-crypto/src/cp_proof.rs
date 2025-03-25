use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_std::UniformRand;
use serde::{Deserialize, Serialize};
use spongefish::{
    DomainSeparator, DuplexSpongeInterface, VerifierState,
    codecs::arkworks_algebra::{
        CommonGroupToUnit, DeserializeField, DeserializeGroup, FieldDomainSeparator, FieldToUnit,
        GroupDomainSeparator, GroupToUnit, UnitToField,
    },
};
use std::marker::PhantomData;

use crate::traits::dleq_proof::{DleqProofError, DleqProofScheme};

/// Chaum-Pedersen proof of discrete log equality.
///
/// Given a tuple (g, g_hat, h, h_hat) prove that DLOG_{g}(g_hat) == DLOG_{h}(h_hat).
///
/// Protocol description (Section 5 in [Sigma.pdf](https://www.cs.au.dk/~ivan/Sigma.pdf)) with additional background on sigma protocols.
pub(crate) struct ChaumPedersen<C, D>
where
    C: CurveGroup,
    D: DuplexSpongeInterface,
{
    _group: PhantomData<C>,
    _hash: PhantomData<D>,
}

pub struct CPParameters<C, D>
where
    C: CurveGroup,
    D: DuplexSpongeInterface,
{
    _hash: PhantomData<D>,
    pub generator: C,
    pub io_pattern: DomainSeparator<D>,
}

impl<C: CurveGroup, D: DuplexSpongeInterface> Clone for CPParameters<C, D> {
    fn clone(&self) -> Self {
        Self {
            _hash: PhantomData,
            generator: self.generator,
            io_pattern: self.io_pattern.clone(),
        }
    }
}

/// Tuple (g, g_hat, h, h_hat)
///
/// subject to proving: DLOG_{g}(g_hat) == DLOG_{h}(h_hat)
#[derive(Clone)]
pub(crate) struct DleqTuple<C: CurveGroup>(C, C, C, C);

impl<C: CurveGroup> DleqTuple<C> {
    pub fn new(g: C, g_hat: C, h: C, h_hat: C) -> Self {
        DleqTuple(g, g_hat, h, h_hat)
    }

    pub fn verify_tuple(&self, x: C::ScalarField) -> bool {
        self.0 * x == self.1 && self.2 * x == self.3
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Proof {
    pub(crate) transcript: Vec<u8>,
}

/// SAFE IO Pattern for the Chaum-Pedersen sigma protocol
/// (see Algorithm 6 in <https://eprint.iacr.org/2023/522.pdf>)
trait ChaumPedersenIOPattern<C: CurveGroup> {
    fn new_cp_proof(domsep: &str) -> Self;
    fn add_cp_statement(self) -> Self;
    fn add_cp_io(self) -> Self;
}

impl<C, D> ChaumPedersenIOPattern<C> for DomainSeparator<D>
where
    C: CurveGroup,
    D: DuplexSpongeInterface,
    DomainSeparator<D>: GroupDomainSeparator<C> + FieldDomainSeparator<C::ScalarField>,
{
    fn new_cp_proof(domsep: &str) -> Self {
        DomainSeparator::new(domsep).add_cp_statement().add_cp_io()
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

impl<C: CurveGroup, D: DuplexSpongeInterface> DleqProofScheme for ChaumPedersen<C, D> {
    type DleqTuple = DleqTuple<C>;
    type Scalar = C::ScalarField;
    type Proof = Proof;

    fn prove(tuple: Self::DleqTuple, x: &Self::Scalar) -> Result<Self::Proof, DleqProofError> {
        if !tuple.verify_tuple(*x) {
            return Err(DleqProofError::Internal(anyhow!(
                "unable to generate proof for invalid tuple"
            )));
        }
        let DleqTuple(g, g_hat, h, h_hat) = tuple;
        let mut merlin = Self::io_pattern().to_prover_state();
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
            transcript: merlin.narg_string().to_vec(),
        })
    }

    fn verify(tuple: DleqTuple<C>, proof: &Self::Proof) -> Result<(), DleqProofError>
    where
        for<'a> VerifierState<'a, D>:
            DeserializeGroup<C> + DeserializeField<C::ScalarField> + UnitToField<C::ScalarField>,
    {
        let mut arthur = Self::io_pattern().to_verifier_state(&proof.transcript);
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

impl<C: CurveGroup, D: DuplexSpongeInterface> ChaumPedersen<C, D> {
    pub(crate) fn io_pattern() -> DomainSeparator<D> {
        <DomainSeparator<D> as ChaumPedersenIOPattern<C>>::new_cp_proof("dleq::chaum-pedersen")
    }
}
#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_std::rand::Rng;
    use ark_std::{UniformRand, test_rng};
    use spongefish::ProverState;
    use spongefish::codecs::arkworks_algebra::{
        CommonGroupToUnit, FieldToUnit, GroupToUnit, UnitToField,
    };
    use spongefish::keccak::Keccak;

    use crate::{
        cp_proof::{ChaumPedersen, DleqTuple, Proof},
        traits::dleq_proof::DleqProofScheme,
    };

    type G = ark_secp256k1::Projective;
    type D = Keccak;
    type S = <ark_secp256k1::Projective as PrimeGroup>::ScalarField;

    #[test]
    fn proof_correctness() {
        let mut rng = test_rng();

        // Setup
        let (x, tuple) = setup(&mut rng);

        // Create proof
        let proof = ChaumPedersen::<G, D>::prove(tuple.clone(), &x).unwrap();

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(tuple, &proof);
        assert!(result.is_ok(), "Proof verification failed");
    }

    #[test]
    fn generate_proof_invalid_tuple() {
        let mut rng = test_rng();

        // Setup
        let (x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, _) = tuple;
        let y = S::from(2);

        // Generate invalid tuple (g, g_hat, h, h_hat)
        let tuple = DleqTuple::new(g, g_hat, h, h * y);

        // Verify proof
        let proof = ChaumPedersen::<G, D>::prove(tuple.clone(), &x);
        assert!(
            proof.is_err(),
            "Proof generation should fail with invalid tuple"
        );
    }

    #[test]
    fn verify_proof_for_invalid_tuple() {
        let mut rng = test_rng();

        let (x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, _) = tuple;

        // Create proof
        let proof = ChaumPedersen::<G, D>::prove(tuple.clone(), &x).unwrap();

        let y = S::rand(&mut rng);
        let tuple_invalid = DleqTuple::new(g, g_hat, h, h * y);
        assert!(!tuple_invalid.verify_tuple(x));
        assert!(!tuple_invalid.verify_tuple(y));

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(tuple_invalid, &proof);
        assert!(
            result.is_err(),
            "Proof verification should fail with invalid tuple"
        );
    }

    #[test]
    fn verify_invalid_proof_for_tuple() {
        let mut rng = test_rng();

        let (x, tuple) = setup(&mut rng);
        let DleqTuple(g, g_hat, h, h_hat) = tuple;

        // Create invalid transcript
        let mut mordred: ProverState<D> = ChaumPedersen::<G, D>::io_pattern().to_prover_state();
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
            transcript: mordred.narg_string().to_vec(),
        };

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(tuple, &mordred_proof);
        assert!(
            result.is_err(),
            "Proof verification should fail with invalid transcript"
        );
    }

    fn setup<R: Rng>(mut rng: R) -> (S, DleqTuple<G>) {
        // Generate random scalar x
        let x = S::rand(&mut rng);

        // Generate tuple (g, g_hat, h, h_hat)
        let g = G::generator();
        let g_hat = g * x;
        let h = G::rand(&mut rng);
        let h_hat = h * x;
        let tuple = DleqTuple::new(g, g_hat, h, h_hat);
        (x, tuple)
    }
}
