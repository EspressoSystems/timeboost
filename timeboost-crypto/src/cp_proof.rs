use std::marker::PhantomData;

use ark_ec::CurveGroup;
use sha2::Digest;

use crate::traits::dleq_proof::{DleqProofError, DleqProofScheme};

pub struct ChaumPedersen<C: CurveGroup, D: Digest> {
    _group: PhantomData<C>,
    _hash: PhantomData<D>,
}

pub struct CPParameters<C: CurveGroup, H: Digest> {
    _hash: PhantomData<H>,
    pub(crate) generator: C,
    pub salt: [u8; 32],
}

// Tuple (g, g_hat, h, h_hat)
// Subject to proving: DLOG_{g}(g_hat) == DLOG_{h}(h_hat)
pub(crate) struct DleqTuple<C: CurveGroup>(C, C, C, C);

impl<C: CurveGroup> DleqTuple<C> {
    pub fn new(g: C, g_hat: C, h: C, h_hat: C) -> Self {
        DleqTuple(g, g_hat, h, h_hat)
    }
}

// Sigma protocol transcript
pub struct Transcript<C: CurveGroup> {
    a: C, // commit
    e: C, // challenge
    z: C, // response
}

pub struct Proof<C: CurveGroup> {
    dleq_tuple: DleqTuple<C>,
    transcript: Transcript<C>,
    meta_data: Vec<u8>,
}

impl<C: CurveGroup, H: Digest> DleqProofScheme for ChaumPedersen<C, H> {
    type Parameters = CPParameters<C, H>;
    type DleqTuple = DleqTuple<C>;
    type Scalar = C::ScalarField;
    type Proof = Proof<C>;

    fn setup<R: rand::Rng>(rng: &mut R) -> Result<Self::Parameters, DleqProofError> {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let generator = C::rand(rng).into();
        Ok(CPParameters {
            _hash: PhantomData,
            generator: generator.into(),
            salt,
        })
    }

    fn prove<R: rand::Rng>(
        rng: &mut R,
        pp: Self::Parameters,
        tuple: Self::DleqTuple,
        x: Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError> {
        // TODO: Generate sigma protocol transcript
        let g = C::generator();
        let transcript = Transcript { a: g, e: g, z: g };

        Ok(Proof {
            dleq_tuple: tuple,
            transcript,
            meta_data: vec![],
        })
    }

    fn verify(pp: Self::Parameters, proof: Self::Proof) -> Result<(), DleqProofError> {
        // TODO: Verify proof
        Ok(())
    }
}
