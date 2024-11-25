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
use nimue::DuplexHash;
use rand::rngs::OsRng;
use sha2::{
    digest::{generic_array::GenericArray, DynDigest, FixedOutputReset},
    Digest,
};
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

/// Shoup-Gennaro [[SG01]](https://www.shoup.net/papers/thresh1.pdf) threshold encryption scheme (TDH2)
/// instantiated as a key encapsulation mechanism (hybrid cryptosystem) for a symmetric key.
pub struct ShoupGennaro<C, H, D>
where
    C: CurveGroup,
    H: Digest + Default + DynDigest + Clone,
    D: DuplexHash,
{
    _group: PhantomData<C>,
    _hash: PhantomData<H>,
    _duplex: PhantomData<D>,
}

#[derive(Clone)]
pub struct Committee {
    pub id: u32,
    pub size: u32,
}

pub struct Parameters<C: CurveGroup, H: Digest, D: DuplexHash> {
    _hash: PhantomData<H>,
    pub committee: Committee,
    pub generator: C,
    pub cp_params: CPParameters<C, D>,
}

pub struct PublicKey<C: CurveGroup> {
    pub pk: C,
    pub pk_comb: Vec<C>,
}
#[derive(Clone)]
pub struct KeyShare<C: CurveGroup> {
    share: C::ScalarField,
    index: u32,
}
#[derive(Debug)]
pub struct Plaintext(Vec<u8>);

pub struct Ciphertext<C: CurveGroup> {
    v: C,
    w_hat: C,
    e: Vec<u8>,
    nonce: Vec<u8>,
    pi: Proof,
}
#[derive(Clone)]
pub struct DecShare<C: CurveGroup> {
    w: C,
    index: u32,
    phi: Proof,
}

impl<C, H, D> ThresholdEncScheme for ShoupGennaro<C, H, D>
where
    H: Digest + Default + DynDigest + Clone + FixedOutputReset + 'static,
    D: DuplexHash,
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    type Committee = Committee;
    type Parameters = Parameters<C, H, D>;
    type PublicKey = PublicKey<C>;
    type KeyShare = KeyShare<C>;
    type Plaintext = Plaintext;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn setup<R: Rng>(
        rng: &mut R,
        committee: Committee,
    ) -> Result<Self::Parameters, ThresholdEncError> {
        let generator: C = C::rand(rng);
        Ok(Parameters {
            _hash: PhantomData::<H>,
            generator,
            committee,
            cp_params: CPParameters::new(generator),
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
        let alpha_0 = poly[0];
        let evals: Vec<_> = (0..committee_size)
            .map(|i| {
                let x = domain.unwrap().element(i);
                poly.evaluate(&x)
            })
            .collect();

        let u_0 = gen * alpha_0;
        let pub_key = PublicKey {
            pk: u_0,
            pk_comb: evals.iter().map(|alpha| gen * alpha).collect(),
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
        let beta = C::ScalarField::rand(rng);
        let v = pp.generator * beta;
        let w = pub_key.pk * beta;

        // hash to symmetric key `k`
        let key = hash_to_key::<C, H>(v, w).unwrap();
        let k = GenericArray::from_slice(&key);

        // AES encrypt using `k`, `nonce` and `message`
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let e = aes_gcm::aead::Aead::encrypt(&cipher, &nonce, message.0.as_ref()).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Unable to encrypt plaintext: {:?}", e))
        })?;
        let u_hat = hash_to_curve::<C, H, D>(v, e.clone(), pp)?;

        let w_hat = u_hat * beta;

        // Produce DLEQ proof for CCA security
        let tuple = DleqTuple::new(pp.generator, v, u_hat, w_hat);
        let pi = ChaumPedersen::<C, D>::prove(&pp.cp_params, tuple, &beta).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Encrypt: Proof generation failed: {:?}", e))
        })?;

        Ok(Ciphertext {
            v,
            w_hat,
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
            ciphertext.pi.clone(),
        );
        let u_hat = hash_to_curve(v, e, pp).unwrap();
        let tuple = DleqTuple::new(pp.generator, v, u_hat, w_hat);
        ChaumPedersen::verify(&pp.cp_params, tuple, &pi)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Invalid proof: {:?}", e)))?;

        let w = v * alpha;
        let u_i = pp.generator * alpha;
        let tuple = DleqTuple::new(pp.generator, u_i, v, w);
        let phi = ChaumPedersen::<C, D>::prove(&pp.cp_params, tuple, &alpha).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Decrypt: Proof generation failed {:?}", e))
        })?;

        Ok(DecShare {
            w,
            index: sk.index,
            phi,
        })
    }

    fn combine(
        pp: &Self::Parameters,
        pub_key: &Self::PublicKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let committee_size: usize = pp.committee.size as usize;
        let threshold = committee_size / CORR_RATIO + 1;

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

        let (v, nonce, data) = (
            ciphertext.v,
            ciphertext.nonce.as_slice(),
            ciphertext.e.clone(),
        );
        let pk_comb = pub_key.pk_comb.clone();

        // Verify DLEQ proofs
        let valid_shares: Vec<_> = dec_shares
            .iter()
            .filter_map(|share| {
                let (w, phi) = (share.w, share.phi.clone());
                let u = pk_comb[share.index as usize];
                let tuple = DleqTuple::new(pp.generator, u, v, w);
                ChaumPedersen::verify(&pp.cp_params, tuple, &phi)
                    .ok()
                    .map(|_| *share)
            })
            .collect();

        if valid_shares.len() < threshold {
            return Err(ThresholdEncError::NotEnoughShares);
        }

        // Colllect eval points for decryption shares
        let x = dec_shares
            .iter()
            .map(|share| domain.element(share.index as usize))
            .collect::<Vec<_>>();

        // Calculating lambdas
        let mut nom = vec![C::ScalarField::one(); threshold];
        let mut denom = vec![C::ScalarField::one(); threshold];
        let mut l = vec![C::ScalarField::zero(); threshold];
        #[allow(clippy::needless_range_loop)]
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

        // Hash to symmetric key `k`
        let key = hash_to_key::<C, H>(v, w).unwrap();
        let k = GenericArray::from_slice(&key);
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let plaintext = aes_gcm::aead::Aead::decrypt(&cipher, nonce.into(), data.as_ref());
        plaintext
            .map(Plaintext)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Decryption failed: {:?}", e)))
    }
}

// TODO: Replace with actual hash to curve
// (see. https://datatracker.ietf.org/doc/rfc9380/)
fn hash_to_curve<C, H, D>(
    v: C,
    e: Vec<u8>,
    pp: &Parameters<C, H, D>,
) -> Result<C, ThresholdEncError>
where
    C: CurveGroup,
    H: Digest + Default + Clone + FixedOutputReset + 'static,
    D: DuplexHash,
{
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    let _ = writer.write(&e);
    writer.flush()?;
    drop(writer);
    let hasher = <DefaultFieldHasher<H> as HashToField<C::ScalarField>>::new(&[0u8]);
    let scalar_from_hash: C::ScalarField = hasher.hash_to_field::<1>(&buffer)[0];
    let u_hat = pp.generator * scalar_from_hash;
    Ok(u_hat)
}

fn hash_to_key<C: CurveGroup, H: Digest>(v: C, w: C) -> Result<Vec<u8>, ThresholdEncError> {
    let mut hasher = H::new();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    w.serialize_compressed(&mut writer)?;
    writer.flush()?;
    drop(writer);
    hasher.update(buffer);
    let key = hasher.finalize();
    Ok(key.to_vec())
}

#[cfg(test)]
mod test {
    use crate::{
        cp_proof::Proof,
        sg_encryption::{Committee, DecShare, Plaintext, ShoupGennaro},
        traits::threshold_enc::ThresholdEncScheme,
    };
    use ark_bn254::G1Projective;

    use ark_std::test_rng;
    use nimue::hash::legacy::DigestBridge;
    use rand::seq::SliceRandom;
    use sha2::Sha256;

    type G = G1Projective;
    type H = Sha256;
    type D = DigestBridge<H>;

    #[test]
    fn test_correctness() {
        let rng = &mut test_rng();
        let committee = Committee { size: 10, id: 0 };

        let parameters = ShoupGennaro::<G, H, D>::setup(rng, committee).unwrap();
        // setup schemes
        let (pk, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &parameters).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &parameters, &pk, &plaintext).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(&parameters, s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message =
            ShoupGennaro::<G, H, D>::combine(&parameters, &pk, dec_shares_refs, &ciphertext)
                .unwrap();
        assert_eq!(
            message, check_message.0,
            "encrypted message:{:?} should be the same as the output of combine: {:?}",
            message, check_message.0
        );
    }

    #[test]
    fn test_not_enough_shares() {
        let rng = &mut test_rng();
        let committee = Committee { size: 10, id: 0 };

        let parameters = ShoupGennaro::<G, H, D>::setup(rng, committee.clone()).unwrap();
        // setup schemes
        let (pk, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &parameters).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &parameters, &pk, &plaintext).unwrap();

        let threshold = (committee.size / 3) as usize;
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(&parameters, s, &ciphertext))
            .filter_map(|res| res.ok())
            .take(threshold) // not enough shares to combine
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let result =
            ShoupGennaro::<G, H, D>::combine(&parameters, &pk, dec_shares_refs, &ciphertext);
        assert!(
            result.is_err(),
            "Should fail to combine; insufficient amount of shares"
        );
    }

    #[test]
    fn test_combine_invalid_shares() {
        let rng = &mut test_rng();
        let committee = Committee { size: 10, id: 0 };

        let parameters = ShoupGennaro::<G, H, D>::setup(rng, committee.clone()).unwrap();
        // setup schemes
        let (pk, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &parameters).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &parameters, &pk, &plaintext).unwrap();

        let mut dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(&parameters, s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        // 1. Change the order of the shares received by combiner
        dec_shares.shuffle(rng);

        let check_message = ShoupGennaro::<G, H, D>::combine(
            &parameters,
            &pk,
            dec_shares.iter().collect(),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "Combine should be indifferent to the order of incoming shares"
        );

        // 2. Invalidate n - t shares
        let committee_size = committee.size as usize;
        let threshold = committee_size / 3;
        let first_correct_share = dec_shares[0].clone();
        // modify n - t shares
        (0..(committee_size - threshold)).for_each(|i| {
            let mut share: DecShare<_> = dec_shares[i].clone();
            share.phi = Proof {
                transcript: vec![],
                _meta_data: vec![],
            };
            dec_shares[i] = share;
        });
        let result = ShoupGennaro::<G, H, D>::combine(
            &parameters,
            &pk,
            dec_shares.iter().collect(),
            &ciphertext,
        );
        assert!(
            result.is_err(),
            "Should fail due to not enough valid shares"
        );
        // 3. Reattach the first correct share to the combining set
        // to obtain exactly t+1 correct shares (enough to combine)
        dec_shares[0] = first_correct_share;
        let result = ShoupGennaro::<G, H, D>::combine(
            &parameters,
            &pk,
            dec_shares.iter().collect(),
            &ciphertext,
        );
        assert!(
            result.is_ok(),
            "Should succeed; we have exactly t+1 valid shares"
        );
    }
}
