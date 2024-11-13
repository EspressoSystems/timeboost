use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    PrimeField, UniformRand,
};
use ark_poly::{domain, Radix2EvaluationDomain};
use ark_poly::{
    polynomial::univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain,
    GeneralEvaluationDomain, Polynomial,
};
use rand::rngs::OsRng;
use rand::Rng;
use sha2::Sha256;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;

use crate::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};

/// tolerate $t<n/3$ and $t+1$ dec shares to recover the plaintext
const THRESHOLD: usize = 3;

pub struct ShoupGennaro<C: CurveGroup> {
    _group: PhantomData<C>,
}

pub struct Committee {
    pub size: usize,
    pub id: usize,
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

pub struct Plaintext(Vec<u8>);

pub struct Ciphertext<C: CurveGroup> {
    v: C::Affine,
    w_hat: C::Affine,
    e: Vec<u8>,
    nonce: Vec<u8>,
    //pi: DLEQProof<C>,
}
pub struct DecShare<C: CurveGroup> {
    w: C::Affine,
    index: u32,
    // phi: DLEQProof<C>,
}
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
    type Committee = Committee;
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type KeyShare = KeyShare<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn setup<R: Rng>(
        committee: Committee,
        rng: &mut R,
    ) -> Result<Self::Parameters, ThresholdEncError> {
        let generator = C::rand(rng).into();
        Ok(Parameters {
            generator,
            committee,
        })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Vec<Self::KeyShare>), ThresholdEncError> {
        let committee_size = pp.committee.size;
        let degree = committee_size / THRESHOLD;
        let poly = DensePolynomial::rand(degree, rng);
        let domain = Radix2EvaluationDomain::new(committee_size);
        if domain.is_none() {
            return Err(ThresholdEncError::Internal(anyhow!(
                "Unable to create eval domain"
            )));
        }

        let evals: Vec<_> = (0..=committee_size)
            .into_iter()
            .map(|i| {
                let x = domain.unwrap().element(i);
                poly.evaluate(&x)
            })
            .collect();
        let length = evals.len();
        assert!(length == committee_size);

        let alpha_0: C::ScalarField = evals[0];
        let u_0 = pp.generator * alpha_0;
        let pub_key = PublicKey {
            pk: u_0.into(),
            pk_comb: evals
                .iter()
                .skip(1)
                .map(|alpha| (pp.generator * alpha).into())
                .collect(),
        };

        let key_shares = evals
            .into_iter()
            .enumerate()
            .skip(1)
            .map(|(i, alpha)| KeyShare {
                share: alpha,
                index: i as u32,
            })
            .collect();

        Ok((pub_key, key_shares))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pub_key: &Self::PublicKey,
        message: &Self::Plaintext,
        beta: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        let v: C = pp.generator * beta.0;
        let _w: C = pub_key.pk * beta.0;
        let committee_id_bytes = pp.committee.id.to_le_bytes();

        // TODO: hash to key space $k = H_1(v,w)$
        let key: &[u8; 32] = &[42; 32]; // should be H_1(v,w)
        let k: &Key<Aes256Gcm> = key.into();

        let cipher = Aes256Gcm::new(&k);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let e = cipher.encrypt(&nonce, message.0.as_ref());
        if e.is_err() {
            return Err(ThresholdEncError::Internal(anyhow!(
                "Unable to encrypt plaintext"
            )));
        }
        let e = e.unwrap();

        // TODO: hash to curve $\hat{u}=H_2(v,e)$
        let mut buffer = Vec::new();
        let mut writer = BufWriter::new(&mut buffer);
        v.serialize_compressed(&mut writer)
            .map_err(|_| ThresholdEncError::Internal(anyhow!("Serialization failed")))?;
        let _ = writer.write(&e);
        drop(writer);
        let hasher =
            <DefaultFieldHasher<Sha256> as HashToField<C::ScalarField>>::new(&committee_id_bytes);
        let scalar_from_hash: C::ScalarField = hasher.hash_to_field(&buffer, 1)[0];
        let u_hat = pp.generator * scalar_from_hash;
        let w_hat = u_hat * beta.0;

        // TODO: pi = DLEQ_PROOF(g, u_hat, v, w_hat)

        Ok(Ciphertext {
            v: v.into(),
            w_hat: w_hat.into(),
            nonce: nonce.to_vec(),
            e,
        })
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::DecShare, ThresholdEncError> {
        let alpha = sk.share;
        let (v, _e, _w_hat) = (ciphertext.v, ciphertext.e.clone(), ciphertext.w_hat);
        // TODO: Verify pi

        let w = v * alpha;
        // TODO: phi = DLEQ_PROOF(g, u, v, w)

        Ok(DecShare {
            w: w.into(),
            index: sk.index,
        })
    }

    fn combine(
        pp: &Self::Parameters,
        _pub_key: &Self::PublicKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let threshold = (pp.committee.size / THRESHOLD) + 1;

        if dec_shares.len() < threshold {
            return Err(ThresholdEncError::NotEnoughShares);
        } else {
            let domain: Radix2EvaluationDomain<C::ScalarField> =
                Radix2EvaluationDomain::new(pp.committee.size).unwrap();

            let x = dec_shares
                .iter()
                .map(|share| domain.element(share.index as usize))
                .collect::<Vec<_>>();

            // Calculating lambdas
            let mut nom = vec![C::ScalarField::zero(); threshold];
            let mut denom = vec![C::ScalarField::zero(); threshold];
            let mut l = vec![C::ScalarField::one(); threshold];
            for i in 0..threshold {
                let x_i = x[i];
                nom[i] = C::ScalarField::one();
                denom[i] = C::ScalarField::one();
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

            // TODO: hash to key space $k = H_1(v,w)$
            let key: &[u8; 32] = &[42; 32]; // should be H_1(v,w)
            let k: &Key<Aes256Gcm> = key.into();

            let data = ciphertext.e.clone();
            let cipher = Aes256Gcm::new(&k);
            let nonce: &[u8] = ciphertext.nonce.as_slice();
            let plaintext = cipher.decrypt(nonce.into(), data.as_ref());
            plaintext
                .map(Plaintext)
                .map_err(|_| ThresholdEncError::Internal(anyhow!("Decryption failed")))
        }
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    use rand::Rng;

    use crate::sg_encryption::{
        Committee, Plaintext, Randomness, ShoupGennaro, ThresholdEncScheme,
    };

    #[test]
    fn test_shoup_gennaro_encryption() {
        let rng = &mut test_rng();
        let committee = Committee { size: 10, id: 0 };
        // setup and key generation
        let parameters = ShoupGennaro::<JubJub>::setup(committee, rng).unwrap();
        let (pk, key_shares) = ShoupGennaro::<JubJub>::keygen(&parameters, rng).unwrap();

        let r = Randomness::rand(rng);
        let message = "important message".as_bytes().to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext = ShoupGennaro::<JubJub>::encrypt(&parameters, &pk, &plaintext, &r).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<JubJub>::decrypt(&parameters, s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();
        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message =
            ShoupGennaro::<JubJub>::combine(&parameters, dec_shares_refs, &ciphertext).unwrap();

        assert_eq!(message, check_message.0);
    }

    impl UniformRand for Plaintext {
        #[inline]
        fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
            let mut bytes = vec![0u8; 32]; // Adjust size as needed
            rng.fill_bytes(&mut bytes);
            Plaintext(bytes)
        }
    }
}
