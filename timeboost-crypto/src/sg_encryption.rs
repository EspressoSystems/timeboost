use aes_gcm::{AeadCore, Aes256Gcm, aead};
use anyhow::anyhow;
use ark_ec::CurveGroup;
use ark_ff::{
    One, PrimeField, UniformRand, batch_inversion,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use ark_poly::EvaluationDomain;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::{DenseUVPolynomial, polynomial::univariate::DensePolynomial};
use ark_std::rand::Rng;
use ark_std::rand::rngs::OsRng;
use digest::{Digest, DynDigest, FixedOutputReset, generic_array::GenericArray};
use spongefish::DuplexSpongeInterface;
use std::marker::PhantomData;
use std::{
    collections::BTreeSet,
    io::{BufWriter, Write},
};
use zeroize::Zeroize;

use crate::{
    Ciphertext, CombKey, DecShare, KeyShare, Keyset, KeysetId, Nonce, Plaintext, PublicKey,
    cp_proof::{ChaumPedersen, DleqTuple},
    traits::{
        dleq_proof::DleqProofScheme,
        threshold_enc::{ThresholdEncError, ThresholdEncScheme},
    },
};

/// Shoup-Gennaro [[SG01]](https://www.shoup.net/papers/thresh1.pdf) threshold encryption scheme (TDH2)
/// instantiated as a key encapsulation mechanism (hybrid cryptosystem) for a symmetric key.
///
/// NOTE:
/// 1. k-out-of-n threshold scheme means >= k correct decryption shares lead to successful `combine()`
///    in the case of timeboost, k=f+1 where f is the (inclusive) faulty nodes
pub struct ShoupGennaro<C, H, D>
where
    C: CurveGroup,
    H: Digest + Default + DynDigest + Clone,
    D: DuplexSpongeInterface,
{
    _group: PhantomData<C>,
    _hash: PhantomData<H>,
    _duplex: PhantomData<D>,
}

impl<C, H, D> ThresholdEncScheme for ShoupGennaro<C, H, D>
where
    H: Digest + Default + DynDigest + Clone + FixedOutputReset + 'static,
    D: DuplexSpongeInterface,
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    type Committee = Keyset;
    type PublicKey = PublicKey<C>;
    type CombKey = CombKey<C>;
    type KeyShare = KeyShare<C>;
    type Plaintext = Plaintext;
    type AssociatedData = Vec<u8>;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn keygen<R: Rng>(
        rng: &mut R,
        committee: &Keyset,
    ) -> Result<(Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>), ThresholdEncError> {
        let committee_size = committee.size.get();
        let degree = committee.one_honest_threshold().get() - 1;
        let generator = C::generator();
        let mut poly: DensePolynomial<_> = DensePolynomial::rand(degree, rng);

        let domain = Radix2EvaluationDomain::<C::ScalarField>::new(committee_size)
            .ok_or_else(|| ThresholdEncError::Internal(anyhow!("Unable to create eval domain")))?;

        let mut alpha_0 = poly[0];
        let mut evals: Vec<_> = domain.fft(&poly);
        evals.truncate(committee_size); // FFT might produce to next_power_of_two(committee_size)

        let u_0 = generator * alpha_0;
        let pub_key = PublicKey { key: u_0 };
        let comb_key = CombKey {
            key: evals.iter().map(|alpha| generator * alpha).collect(),
        };

        let key_shares = evals
            .into_iter()
            .enumerate()
            .map(|(i, alpha)| KeyShare {
                share: alpha,
                index: i as u32,
            })
            .collect();

        alpha_0.zeroize();
        poly.coeffs.zeroize();
        Ok((pub_key, comb_key, key_shares))
    }

    fn encrypt<R: Rng>(
        rng: &mut R,
        kid: &KeysetId,
        pub_key: &Self::PublicKey,
        message: &Self::Plaintext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        let beta = C::ScalarField::rand(rng);
        let generator = C::generator();
        let v = generator * beta;
        let w = pub_key.key * beta;

        // hash to symmetric key `k`
        // TODO: (alex) consider moving kid as part of `aad` instead
        let key = hash_to_key::<C, H>(v, w, (*kid).into())
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);

        // TODO: use committee id for hashing

        // AES encrypt using `k`, `nonce` and `message`
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let nonce = Nonce::from(Aes256Gcm::generate_nonce(OsRng));
        let payload = aead::Payload {
            msg: &message.0,
            aad,
        };
        let e = aes_gcm::aead::Aead::encrypt(&cipher, &nonce.into(), payload).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Unable to encrypt plaintext: {:?}", e))
        })?;
        let u_hat = hash_to_curve::<C, H>(v, e.clone())?;

        let w_hat = u_hat * beta;

        // Produce DLEQ proof for CCA security
        let tuple = DleqTuple::new(generator, v, u_hat, w_hat);
        let pi = ChaumPedersen::<C, D>::prove(tuple, &beta).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Encrypt: Proof generation failed: {:?}", e))
        })?;

        Ok(Ciphertext {
            v,
            w_hat,
            nonce,
            e,
            pi,
        })
    }

    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::DecShare, ThresholdEncError> {
        // NOTE: our scheme can optionally reject decryption request based on the `aad` value
        // e.g. `aad` includes an invalid credential, coming from an unauthorized prying combiner
        let generator = C::generator();
        let alpha = sk.share;
        let v = ciphertext.v;

        // check ciphertext integrity against associated data
        Self::ct_check(ciphertext, aad)?;

        let w = v * alpha;
        let u_i = generator * alpha;
        let tuple = DleqTuple::new(generator, u_i, v, w);
        let phi =
            ChaumPedersen::<C, D>::prove(tuple, &alpha).map_err(ThresholdEncError::DleqError)?;

        Ok(DecShare {
            w,
            index: sk.index,
            phi,
        })
    }

    fn combine(
        committee: &Keyset,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let committee_size: usize = committee.size.get();
        let threshold = committee.one_honest_threshold().get();
        let generator = C::generator();

        // check ciphertext integrity against associated data
        Self::ct_check(ciphertext, aad)?;

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
            &ciphertext.nonce.into() as &GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>,
            ciphertext.e.clone(),
        );
        let pk_comb = comb_key.key.clone();

        // Verify DLEQ proofs to ensure correctness of the decryption share w_i
        // keeping a list of faulty shares (their node indices) to blame
        let mut valid_shares = Vec::new();
        let mut faulty_shares = Vec::new();
        for share in &dec_shares {
            let (w, phi) = (share.w, &share.phi);
            let u = pk_comb.get(share.index as usize).ok_or_else(|| {
                ThresholdEncError::Argument(format!("CombKey missing idx: {}", share.index))
            })?;

            let tuple = DleqTuple::new(generator, *u, v, w);
            if ChaumPedersen::<C, D>::verify(tuple, phi).is_ok() {
                valid_shares.push(share);
            } else {
                faulty_shares.push(share);
            }
        }

        let mut faulty_subset = BTreeSet::new();
        for s in faulty_shares {
            faulty_subset.insert(s.index);
        }
        if valid_shares.len() < threshold {
            return Err(ThresholdEncError::FaultySubset(faulty_subset));
        }

        // Collect eval points for decryption shares
        let x = dec_shares
            .iter()
            .map(|share| domain.element(share.index as usize))
            .collect::<Vec<_>>();

        // Calculate lagrange coefficients using barycentric form
        let l = {
            // l(0) = \prod {0-x_i} is common to all basis
            let l_common = x[..threshold]
                .iter()
                .fold(C::ScalarField::one(), |acc, x_i| acc * (-*x_i));

            // w: barycentric weights
            let mut w = vec![C::ScalarField::one(); threshold];
            for i in 0..threshold {
                for j in 0..threshold {
                    if i != j {
                        w[i] *= x[i] - x[j];
                    }
                }
            }
            batch_inversion(&mut w);

            x.iter()
                .zip(w.iter())
                .map(|(x_i, w_i)| l_common * w_i / (-*x_i))
                .collect::<Vec<_>>()
        };

        // Lagrange interpolation in the exponent
        let w = C::msm(
            &dec_shares[..threshold]
                .iter()
                .map(|share| share.w.into_affine())
                .collect::<Vec<_>>(),
            &l,
        )
        .map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Interpolate in the exponent failed: {:?}", e))
        })?;

        // Hash to symmetric key `k`
        let key = hash_to_key::<C, H>(v, w, committee.id.into())
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);

        let payload = aead::Payload { msg: &data, aad };
        let plaintext = aes_gcm::aead::Aead::decrypt(&cipher, nonce, payload).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Symmetric decrypt failed: {:?}", e))
        })?;
        Ok(Plaintext(plaintext))
    }
}

impl<C, H, D> ShoupGennaro<C, H, D>
where
    C: CurveGroup,
    H: Digest + Default + DynDigest + Clone + FixedOutputReset + 'static,
    D: DuplexSpongeInterface,
{
    /// Check correctness of ciphertext against its associated data (or "Label" in [SG01])
    /// through Dleq proof verification.
    /// This check verifies integrity of the ciphertext w.r.t. the associated data: keyset_id
    fn ct_check(
        ct: &Ciphertext<C>,
        _aad: &<Self as ThresholdEncScheme>::AssociatedData,
    ) -> Result<(), ThresholdEncError> {
        let g = C::generator();
        let (v, e, w_hat, pi) = (ct.v, ct.e.clone(), ct.w_hat, ct.pi.clone());

        // dev note: currently our scheme binds the keyset_id associated data not through `aad`
        // but through symmetric key derivation used to compute `e`, thus `e` indirectly binds `keyset_id`,
        // which is why `aad` is left unused. Technically, keyset_id is part of aad, we should use aad to derive u_hat
        let u_hat = hash_to_curve::<C, H>(v, e)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to curve failed: {:?}", e)))?;
        let tuple = DleqTuple::new(g, v, u_hat, w_hat);
        ChaumPedersen::<C, D>::verify(tuple, &pi).map_err(ThresholdEncError::DleqError)?;

        Ok(())
    }
}

// TODO: Replace with actual hash to curve
// (see. https://datatracker.ietf.org/doc/rfc9380/)
fn hash_to_curve<C, H>(v: C, e: Vec<u8>) -> Result<C, ThresholdEncError>
where
    C: CurveGroup,
    H: Digest + Default + Clone + FixedOutputReset + 'static,
{
    let generator = C::generator();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    let _ = writer.write(&e);
    writer.flush()?;
    drop(writer);
    let hasher = <DefaultFieldHasher<H> as HashToField<C::ScalarField>>::new(&[0u8]);
    let scalar_from_hash: C::ScalarField = hasher.hash_to_field::<1>(&buffer)[0];
    let u_hat = generator * scalar_from_hash;
    Ok(u_hat)
}

fn hash_to_key<C: CurveGroup, H: Digest>(
    v: C,
    w: C,
    id: u64,
) -> Result<Vec<u8>, ThresholdEncError> {
    let mut hasher = H::new();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    w.serialize_compressed(&mut writer)?;
    writer.write_all(&id.to_be_bytes())?;
    writer.flush()?;
    drop(writer);
    hasher.update(buffer);
    let key = hasher.finalize();
    Ok(key.to_vec())
}

#[cfg(test)]
mod test {
    use std::{collections::BTreeSet, num::NonZeroUsize};

    use crate::{
        cp_proof::Proof,
        sg_encryption::{DecShare, Keyset, Plaintext, ShoupGennaro},
        traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme},
    };

    use ark_std::rand::seq::SliceRandom;
    use ark_std::test_rng;
    use sha2::Sha256;
    use spongefish::DigestBridge;

    type G = ark_secp256k1::Projective;
    type H = Sha256;
    type D = DigestBridge<H>;

    #[test]
    fn test_correctness() {
        let rng = &mut test_rng();
        let committee = Keyset::new(0, NonZeroUsize::new(20).unwrap());

        // setup schemes
        let (pk, comb_key, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let aad = b"cred~abcdef".to_vec();
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares_refs.clone(),
            &ciphertext,
            &aad,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "encrypted message:{:?} should be the same as the output of combine: {:?}",
            message, check_message.0
        );

        // make sure that wrong associated data will fail decryption
        assert!(
            ShoupGennaro::<G, H, D>::combine(
                &committee,
                &comb_key,
                dec_shares_refs,
                &ciphertext,
                b"cred~bad".to_vec().as_ref(),
            )
            .is_err()
        );
    }

    #[test]
    fn test_not_enough_shares() {
        let rng = &mut test_rng();
        let committee = Keyset::new(0, NonZeroUsize::new(10).unwrap());

        // setup schemes
        let (pk, comb_key, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let aad = b"cred~abcdef".to_vec();
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad).unwrap();

        let threshold = committee.one_honest_threshold().get();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .take(threshold - 1) // not enough shares to combine
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let result = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares_refs,
            &ciphertext,
            &aad,
        );
        assert!(
            result.is_err(),
            "Should fail to combine; insufficient amount of shares"
        );
    }

    #[test]
    // NOTE: we are using (t, N) threshold scheme, where exactly =t valid shares can successfully decrypt,
    // in the context of timeboost, t=f+1 where f is the upper bound of faulty nodes. In the original spec,
    // authors used `t+1` shares to decrypt, but here, we are testing SG01 scheme purely from the perspective
    // of the standalone cryptographic scheme, so be aware of the slight mismatch of notation.
    fn test_combine_invalid_shares() {
        let rng = &mut test_rng();
        let committee = Keyset::new(0, NonZeroUsize::new(10).unwrap());

        // setup schemes
        let (pk, comb_key, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let aad = b"cred~abcdef".to_vec();
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad).unwrap();

        let mut dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        // 1. Change the order of the shares received by combiner
        dec_shares.shuffle(rng);

        let check_message = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "Combine should be indifferent to the order of incoming shares"
        );

        // 2. Invalidate n - t + 1 shares (left with t-1 valid shares)
        let c_size = committee.size().get();
        let c_threshold = committee.one_honest_threshold().get();
        let first_correct_share = dec_shares[0].clone();
        // modify the first n - t + 1 shares
        let mut expected_faulty_subset = BTreeSet::new();
        (0..(c_size - c_threshold + 1)).for_each(|i| {
            let mut share: DecShare<_> = dec_shares[i].clone();
            expected_faulty_subset.insert(share.index);
            share.phi = Proof { transcript: vec![] };
            dec_shares[i] = share;
        });
        let result = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        );
        match result {
            Err(ThresholdEncError::FaultySubset(set)) => {
                assert_eq!(set, expected_faulty_subset);
            }
            _ => panic!("Should fail with faulty subset to blame"),
        };
        // 3. Reattach the first correct share to the combining set
        // to obtain exactly t correct shares (enough to combine)
        dec_shares[0] = first_correct_share;
        let result = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        );
        assert!(
            result.is_ok(),
            "Should succeed; we have exactly t+1 valid shares"
        );
    }
}
