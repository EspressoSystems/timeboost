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

// Tuple (g, g_hat, h, h_hat)
// Subject to proving: DLOG_{g}(g_hat) == DLOG_{h}(h_hat)
#[derive(Clone)]
pub struct DleqTuple<C: CurveGroup>(C, C, C, C);

impl<C: CurveGroup> DleqTuple<C> {
    pub fn new(g: C, g_hat: C, h: C, h_hat: C) -> Self {
        DleqTuple(g, g_hat, h, h_hat)
    }
}

#[derive(Clone)]
pub struct Proof {
    transcript: Vec<u8>,
    _meta_data: Vec<u8>,
}

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

    fn setup<R: rand::Rng>(rng: &mut R) -> Result<Self::Parameters, DleqProofError> {
        let generator: C = C::rand(rng);
        Ok(CPParameters::new(generator))
    }

    fn prove(
        pp: &Self::Parameters,
        tuple: Self::DleqTuple,
        x: &Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError> {
        let mut merlin = pp.io_pattern.to_merlin();
        let DleqTuple(g, g_hat, h, h_hat) = tuple;
        merlin.public_points(&[g, g_hat, h, h_hat]).unwrap();
        merlin.ratchet().unwrap();

        let k: C::ScalarField = C::ScalarField::rand(merlin.rng());
        let a = g * k;
        let a_hat = h * k;
        merlin.add_points(&[a, a_hat]).unwrap();

        let [e]: [C::ScalarField; 1] = merlin.challenge_scalars().unwrap();

        let z: C::ScalarField = k + e * x;
        merlin.add_scalars(&[z]).unwrap();
        Ok(Proof {
            transcript: merlin.transcript().to_vec(),
            _meta_data: vec![],
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
        arthur.public_points(&[g, g_hat, h, h_hat]).unwrap();
        arthur.ratchet().unwrap();

        let [a, a_hat] = arthur.next_points().unwrap();
        let [e] = arthur.challenge_scalars().unwrap();
        let [z] = arthur.next_scalars().unwrap();
        if g * z == a + g_hat * e && h * z == a_hat + h_hat * e {
            Ok(())
        } else {
            Err(DleqProofError::ProofNotValid)
        }
    }
}

#[cfg(test)]
mod tests {

    use ark_bn254::G1Projective;
    use ark_ec::{bn::BnConfig, short_weierstrass::Projective, PrimeGroup};
    use ark_std::{test_rng, UniformRand};
    use nimue::hash::Keccak;

    use crate::{
        cp_proof::{ChaumPedersen, DleqTuple},
        traits::dleq_proof::DleqProofScheme,
    };

    #[test]
    fn test_chaum_pedersen_proof() {
        let mut rng = test_rng();

        type G = G1Projective;
        type D = Keccak;
        // Setup parameters
        let params = ChaumPedersen::<G, D>::setup(&mut rng).unwrap();

        // Generate random scalar x
        let x =
            <<Projective<<ark_bn254::Config as BnConfig>::G1Config> as PrimeGroup>::ScalarField>::rand(&mut rng);

        // Generate tuple (g, g_hat, h, h_hat)
        let g = params.generator;
        let g_hat = g * x;
        let h = G1Projective::rand(&mut rng);
        let h_hat = h * x;
        let tuple = DleqTuple::new(g, g_hat, h, h_hat);

        // Create proof
        let proof = ChaumPedersen::<G, D>::prove(&params, tuple.clone(), &x).unwrap();

        // Verify proof
        let result = ChaumPedersen::<G, D>::verify(&params, tuple, &proof);
        assert!(result.is_ok(), "Proof verification failed");
    }
}
