use aes_gcm::{AeadCore, Aes256Gcm};
use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    One, PrimeField, UniformRand, Zero,
};
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::{polynomial::univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::rand::Rng;
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use std::io::{BufWriter, Write};
use std::marker::PhantomData;

use crate::{
    cp_proof::{CPParameters, ChaumPedersen, DleqTuple, Proof},
    traits::{
        dleq_proof::DleqProofScheme,
        threshold_enc::{ThresholdEncError, ThresholdEncScheme},
    },
};

/// Corruption ratio.
/// Tolerate t < n/3 and t+1 dec shares to recover the plaintext
const CORR_RATIO: usize = 3;

pub struct ShoupGennaro<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub struct Committee {
    pub size: u32,
    pub id: u32,
}

pub struct Parameters<C: CurveGroup> {
    pub committee: Committee,
    pub generator: C::Affine,
}

pub struct PublicKey<C: CurveGroup> {
    pub pk: C::Affine,
    pub pk_comb: Vec<C::Affine>,
}
#[derive(Clone)]
pub struct KeyShare<C: CurveGroup> {
    share: C::ScalarField,
    index: u32,
}
#[derive(Debug)]
pub struct Plaintext(Vec<u8>);

pub struct Ciphertext<C: CurveGroup> {
    v: C::Affine,
    w_hat: C::Affine,
    e: Vec<u8>,
    nonce: Vec<u8>,
    pi: Proof<C>,
}
pub struct DecShare<C: CurveGroup> {
    w: C::Affine,
    index: u32,
    phi: Proof<C>,
}
pub struct Randomness<C: CurveGroup>(C::ScalarField);

impl<C: CurveGroup> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(C::ScalarField::rand(rng))
    }
}

impl<C> ThresholdEncScheme for ShoupGennaro<C>
where
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    type Committee = Committee;
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type KeyShare = KeyShare<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn setup<R: Rng>(rng: R, committee: Committee) -> Result<Self::Parameters, ThresholdEncError> {
        let generator = C::generator().into();
        Ok(Parameters {
            generator,
            committee,
        })
    }

    fn keygen<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
    ) -> Result<(Self::PublicKey, Vec<Self::KeyShare>), ThresholdEncError> {
        let committee_size = pp.committee.size as usize;
        let degree = committee_size / CORR_RATIO;
        let gen = pp.generator;
        let poly: DensePolynomial<_> = DensePolynomial::rand(degree, rng);
        let domain = Radix2EvaluationDomain::<C::ScalarField>::new(committee_size);

        if domain.is_none() {
            return Err(ThresholdEncError::Internal(anyhow!(
                "Unable to create eval domain"
            )));
        }
        let alpha = poly.evaluate(&C::ScalarField::zero());
        let evals: Vec<_> = (0..committee_size)
            .into_iter()
            .map(|i| {
                let x = domain.unwrap().element(i);
                poly.evaluate(&x)
            })
            .collect();

        let u_0 = gen * alpha;
        let pub_key = PublicKey {
            pk: u_0.into(),
            pk_comb: evals.iter().map(|alpha| (gen * alpha).into()).collect(),
        };

        let key_shares = evals
            .into_iter()
            .enumerate()
            .map(|(i, alpha)| KeyShare {
                share: alpha,
                index: i as u32,
            })
            .collect();

        Ok((pub_key, key_shares))
    }

    fn encrypt<R: Rng>(
        rng: &mut R,
        pp: &Self::Parameters,
        pub_key: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        let beta = C::rand(rng);
        let v: C = pp.generator * beta;
        let w: C = pub_key.pk * beta;

        // hash to symmetric key `k`
        let key = hash_to_key(v, w).unwrap();
        let k = GenericArray::from_slice(&key);

        // AES encrypt using `k`, `nonce` and `message`
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let e = aes_gcm::aead::Aead::encrypt(&cipher, &nonce, message.0.as_ref());
        if e.is_err() {
            return Err(ThresholdEncError::Internal(anyhow!(
                "Unable to encrypt plaintext"
            )));
        }
        let e = e.unwrap();
        let u_hat = hash_to_curve(v, e.clone(), pp)?;

        let w_hat = u_hat * beta.0;

        // Produce DLEQ proof for CCA security
        let cp_params = CPParameters {
            generator: pp.generator.into(),
        };
        let tuple = DleqTuple::new(pp.generator.into(), v, pub_key.pk.into(), w);
        let pi = ChaumPedersen::<C>::prove::<R>(cp_params, tuple, beta.0)
            .map_err(|_| ThresholdEncError::Internal(anyhow!("Proof generation failed")))?;

        Ok(Ciphertext {
            v: v.into(),
            w_hat: w_hat.into(),
            nonce: nonce.to_vec(),
            e,
            pi,
        })
    }

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError> {
        let alpha = sk.share;
        let (v, e, w_hat, pi) = (
            ciphertext.v,
            ciphertext.e.clone(),
            ciphertext.w_hat,
            ciphertext.pi,
        );

        let w = v * alpha;
        let u_i = pp.generator * alpha;
        let tuple = DleqTuple::new(pp.generator.into(), u_i, v, w);
        let cp_params = CPParameters {
            generator: pp.generator.into(),
        };
        let phi = ChaumPedersen::<C>::prove(cp_params, tuple, alpha)
            .map_err(|_| ThresholdEncError::Internal(anyhow!("Proof generation failed")))?;

        Ok(DecShare {
            w: w.into(),
            index: sk.index,
            phi,
        })
    }

    fn combine(
        pp: &Self::Parameters,
        _pub_key: &Self::PublicKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let committee_size: usize = pp.committee.size as usize;
        let threshold = (committee_size / CORR_RATIO + 1) as usize;

        if dec_shares.len() < threshold {
            return Err(ThresholdEncError::NotEnoughShares);
        }
        let domain: Radix2EvaluationDomain<C::ScalarField> =
            Radix2EvaluationDomain::new(committee_size).ok_or_else(|| {
                ThresholdEncError::Internal(anyhow!(
                    "Unable to create eval domain for size {:?}",
                    committee_size
                ))
            })?;

        // Colllect eval points for decryption shares
        let x = dec_shares
            .iter()
            .map(|share| domain.element(share.index as usize))
            .collect::<Vec<_>>();

        // Calculating lambdas
        let mut nom = vec![C::ScalarField::one(); threshold];
        let mut denom = vec![C::ScalarField::one(); threshold];
        let mut l = vec![C::ScalarField::zero(); threshold];
        for i in 0..threshold {
            let x_i = x[i];
            for j in 0..threshold {
                if j == i {
                    continue;
                } else {
                    let x_j = x[j];
                    nom[i] *= C::ScalarField::zero() - x_j;
                    denom[i] *= x_i - x_j;
                }
            }
            l[i] = nom[i] / denom[i];
        }

        // Lagrange interpolation in the exponent
        let mut w = dec_shares[0].w * l[0];
        for d in 1..threshold {
            let w_i = dec_shares[d].w;
            let l_i = l[d];
            w += (w_i * l_i).into();
        }

        // parse ciphertext
        let (v, nonce, data) = (
            ciphertext.v.into(),
            ciphertext.nonce.as_slice(),
            ciphertext.e.clone(),
        );

        // hash to symmetric key `k`
        let key = hash_to_key(v, w).unwrap();
        let k = GenericArray::from_slice(&key);
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(&k);
        let plaintext = aes_gcm::aead::Aead::decrypt(&cipher, nonce.into(), data.as_ref());
        plaintext
            .map(Plaintext)
            .map_err(|_| ThresholdEncError::Internal(anyhow!("Decryption failed")))
    }
}

// TODO: Replace with actual hash to curve
// (see. https://datatracker.ietf.org/doc/rfc9380/)
fn hash_to_curve<C: CurveGroup>(
    v: C,
    e: Vec<u8>,
    pp: &Parameters<C>,
) -> Result<C, ThresholdEncError> {
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)
        .map_err(|_| ThresholdEncError::Internal(anyhow!("Serialization failed")))?;
    let _ = writer.write(&e);
    drop(writer);
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<C::ScalarField>>::new(&[0u8]);
    let scalar_from_hash: C::ScalarField = hasher.hash_to_field(&buffer, 1)[0];
    let u_hat = pp.generator * scalar_from_hash;
    Ok(u_hat)
}

fn hash_to_key<C: CurveGroup>(v: C, w: C) -> Result<Vec<u8>, ThresholdEncError> {
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)
        .map_err(|_| ThresholdEncError::Internal(anyhow!("Serialization failed")))?;
    w.serialize_compressed(&mut writer)
        .map_err(|_| ThresholdEncError::Internal(anyhow!("Serialization failed")))?;
    writer
        .flush()
        .map_err(|_| ThresholdEncError::Internal(anyhow!("Flush failed")))?;
    drop(writer);
    hasher.update(buffer);
    let key = hasher.finalize();
    Ok(key.to_vec())
}

#[cfg(test)]
mod test {
    use crate::sg_encryption::{
        Committee, Plaintext, Randomness, ShoupGennaro, ThresholdEncScheme,
    };
    use ark_bn254::G1Projective;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_shoup_gennaro_encryption() {
        let rng = &mut test_rng();
        let committee = Committee { size: 10, id: 0 };
        // setup and key generation
        let parameters = ShoupGennaro::<G1Projective>::setup(committee).unwrap();
        let (pk, key_shares) = ShoupGennaro::<G1Projective>::keygen(&parameters, rng).unwrap();
        let r = Randomness::rand(rng);
        let message = "important message".as_bytes().to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G1Projective>::encrypt(&parameters, &pk, &plaintext, &r).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G1Projective>::decrypt(&parameters, s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message =
            ShoupGennaro::<G1Projective>::combine(&parameters, &pk, dec_shares_refs, &ciphertext)
                .unwrap();
        assert_eq!(message, check_message.0);
    }
}
