use std::marker::PhantomData;

use ark_ec::CurveGroup;
use sha2::Digest;

use crate::traits::dleq_proof::{DleqProofError, DleqProofScheme};

pub struct ChaumPedersen<C, H>
where
    C: CurveGroup,
    H: Digest,
{
    _group: PhantomData<C>,
    _hash: PhantomData<H>,
}

pub struct CPParameters<C: CurveGroup, H: Digest> {
    _hash: PhantomData<H>,
    pub generator: C,
    pub salt: [u8; 32],
}

impl<C: CurveGroup, H: Digest> Clone for CPParameters<C, H> {
    fn clone(&self) -> Self {
        Self {
            _hash: self._hash.clone(),
            generator: self.generator.clone(),
            salt: self.salt.clone(),
        }
    }
}

impl<C: CurveGroup, H: Digest> CPParameters<C, H> {
    pub fn new(generator: C, salt: [u8; 32]) -> Self {
        Self {
            _hash: PhantomData,
            generator,
            salt,
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

// Sigma protocol transcript
#[derive(Clone)]
#[allow(dead_code)]
pub struct Transcript<C: CurveGroup> {
    commit: C,    // a
    challenge: C, // e
    response: C,  // z
}

#[derive(Clone)]
#[allow(dead_code)]

pub struct Proof<C: CurveGroup> {
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
        _rng: &mut R,
        _pp: &Self::Parameters,
        _tuple: &Self::DleqTuple,
        _x: &Self::Scalar,
    ) -> Result<Self::Proof, DleqProofError> {
        // TODO: Generate real sigma protocol transcript
        let g = C::generator();
        let transcript = Transcript {
            commit: g,
            challenge: g,
            response: g,
        };

        Ok(Proof {
            transcript,
            meta_data: vec![],
        })
    }

    fn verify(
        _pp: &Self::Parameters,
        _tuple: &DleqTuple<C>,
        _proof: &Self::Proof,
    ) -> Result<(), DleqProofError> {
        // TODO: Correctly verify proof
        // For now all proofs are verified as trivially true
        Ok(())
    }
}
