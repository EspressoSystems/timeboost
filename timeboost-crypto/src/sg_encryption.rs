use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use rand::Rng;

use crate::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};

/// tolerate $t<n/3$ and $t+1$ dec shares to recover the plaintext
const THRESHOLD: usize = 3;

pub struct ShoupGennaro<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub struct Parameters<C: CurveGroup> {
    pub committee_size: usize,
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;
pub struct SecretKey<C: CurveGroup>(C::ScalarField);
pub type Plaintext<C> = <C as CurveGroup>::Affine;
pub type Ciphertext<C> = (<C as CurveGroup>::Affine, <C as CurveGroup>::Affine);
pub struct DecShare<C: CurveGroup>(C::Affine);
pub struct Randomness<C: CurveGroup>(C::ScalarField);

impl<C: CurveGroup> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(C::ScalarField::rand(rng))
    }
}

impl<C: CurveGroup> ThresholdEncScheme for ShoupGennaro<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;
    type DecShare = Plaintext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, ThresholdEncError> {
        let generator = C::rand(rng).into();
        Ok(Parameters {
            generator,
            committee_size: 10,
        })
    }

    fn keygen<R: Rng>(
        params: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), ThresholdEncError> {
        let sk = C::ScalarField::rand(rng);
        let pk = params.generator * sk;
        Ok((pk.into(), SecretKey(sk)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        // s = r * pk
        let s = *pk * r.0;

        // compute c1 = r * generator
        let c1 = pp.generator * r.0;

        // compute c2 = m + s
        let c2 = *message + s;

        Ok((c1.into(), c2.into()))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError> {
        let c1: <C as CurveGroup>::Affine = ciphertext.0;
        let c2: <C as CurveGroup>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1 * sk.0;
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv;

        Ok(m.into())
    }

    fn combine(
        _pp: &Self::Parameters,
        dec_shares: Vec<&Self::DecShare>,
        _ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        if dec_shares.len() < THRESHOLD + 1 {
            return Err(ThresholdEncError::NotEnoughShares);
        } else {
            // todo: just summing shares for now
            let mut sum = C::zero();
            for share in dec_shares {
                sum += *share;
            }
            Ok(sum.into())
        }
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bn254::EdwardsProjective as JubJub;

    use crate::sg_encryption::{Randomness, ShoupGennaro, ThresholdEncScheme};

    #[test]
    fn test_shoup_gennaro_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = ShoupGennaro::<JubJub>::setup(rng).unwrap();
        let (pk, sk) = ShoupGennaro::<JubJub>::keygen(&parameters, rng).unwrap();

        // get a random msg and encryption randomness
        let msg = JubJub::rand(rng).into();
        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher = ShoupGennaro::<JubJub>::encrypt(&parameters, &pk, &msg, &r).unwrap();
        let check_msg = ShoupGennaro::<JubJub>::decrypt(&parameters, &sk, &cipher).unwrap();

        assert_eq!(msg, check_msg);
    }
}
