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
use ark_std::rand::rngs::OsRng;
use ark_std::rand::Rng;
use digest::{generic_array::GenericArray, Digest, DynDigest, FixedOutputReset};
use nimue::DuplexHash;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;

use crate::{
    cp_proof::{ChaumPedersen, DleqTuple},
    traits::{
        dleq_proof::DleqProofScheme,
        threshold_enc::{ThresholdEncError, ThresholdEncScheme},
    },
    Ciphertext, CombKey, DecShare, KeyShare, Keyset, Nonce, Plaintext, PublicKey,
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

impl<C, H, D> ThresholdEncScheme for ShoupGennaro<C, H, D>
where
    H: Digest + Default + DynDigest + Clone + FixedOutputReset + 'static,
    D: DuplexHash,
    C: CurveGroup,
    C::ScalarField: PrimeField,
{
    type Committee = Keyset;
    type PublicKey = PublicKey<C>;
    type CombKey = CombKey<C>;
    type KeyShare = KeyShare<C>;
    type Plaintext = Plaintext;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn keygen<R: Rng>(
        rng: &mut R,
        committee: &Keyset,
    ) -> Result<(Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>), ThresholdEncError> {
        let committee_size = committee.size.get();
        let degree = committee_size / CORR_RATIO;
        let gen = C::generator();
        let poly: DensePolynomial<_> = DensePolynomial::rand(degree, rng);

        let domain = Radix2EvaluationDomain::<C::ScalarField>::new(committee_size)
            .ok_or_else(|| ThresholdEncError::Internal(anyhow!("Unable to create eval domain")))?;

        let alpha_0 = poly[0];
        let evals: Vec<_> = (0..committee_size)
            .map(|i| {
                let x = domain.element(i);
                poly.evaluate(&x)
            })
            .collect();

        let u_0 = gen * alpha_0;
        let pub_key = PublicKey { key: u_0 };
        let comb_key = CombKey {
            key: evals.iter().map(|alpha| gen * alpha).collect(),
        };

        let key_shares = evals
            .into_iter()
            .enumerate()
            .map(|(i, alpha)| KeyShare {
                share: alpha,
                index: i as u32,
            })
            .collect();

        Ok((pub_key, comb_key, key_shares))
    }

    fn encrypt<R: Rng>(
        rng: &mut R,
        committee: &Keyset,
        pub_key: &Self::PublicKey,
        message: &Self::Plaintext,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        let beta = C::ScalarField::rand(rng);
        let gen = C::generator();
        let v = gen * beta;
        let w = pub_key.key * beta;
        let cid = committee.id;

        // hash to symmetric key `k`
        let key = hash_to_key::<C, H>(v, w, cid.into())
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);

        // TODO: use committee id for hashing

        // AES encrypt using `k`, `nonce` and `message`
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let nonce = Nonce::from(Aes256Gcm::generate_nonce(OsRng));
        let e = aes_gcm::aead::Aead::encrypt(&cipher, &nonce.into(), message.0.as_ref()).map_err(
            |e| ThresholdEncError::Internal(anyhow!("Unable to encrypt plaintext: {:?}", e)),
        )?;
        let u_hat = hash_to_curve::<C, H>(v, e.clone())?;

        let w_hat = u_hat * beta;

        // Produce DLEQ proof for CCA security
        let tuple = DleqTuple::new(gen, v, u_hat, w_hat);
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
    ) -> Result<Self::DecShare, ThresholdEncError> {
        let gen = C::generator();
        let alpha = sk.share;
        let (v, e, w_hat, pi) = (
            ciphertext.v,
            ciphertext.e.clone(),
            ciphertext.w_hat,
            ciphertext.pi.clone(),
        );
        let u_hat = hash_to_curve::<C, H>(v, e)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to curve failed: {:?}", e)))?;
        let tuple = DleqTuple::new(gen, v, u_hat, w_hat);
        ChaumPedersen::<C, D>::verify(tuple, &pi)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Invalid proof: {:?}", e)))?;

        let w = v * alpha;
        let u_i = gen * alpha;
        let tuple = DleqTuple::new(gen, u_i, v, w);
        let phi = ChaumPedersen::<C, D>::prove(tuple, &alpha).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Decrypt: Proof generation failed {:?}", e))
        })?;

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
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let committee_size: usize = committee.size.get();
        let threshold = committee_size / CORR_RATIO + 1;
        let gen = C::generator();

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

        // Verify DLEQ proofs
        let valid_shares: Vec<_> = dec_shares
            .iter()
            .filter_map(|share| {
                let (w, phi) = (share.w, share.phi.clone());
                let u = pk_comb[share.index as usize];
                let tuple = DleqTuple::new(gen, u, v, w);
                ChaumPedersen::<C, D>::verify(tuple, &phi)
                    .ok()
                    .map(|_| *share)
            })
            .collect();

        if valid_shares.len() < threshold {
            return Err(ThresholdEncError::NotEnoughShares);
        }

        // Collect eval points for decryption shares
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
        let mut w = C::zero();
        for d in 0..threshold {
            let w_i = dec_shares[d].w;
            let l_i = l[d];
            w += w_i * l_i;
        }

        // Hash to symmetric key `k`
        let key = hash_to_key::<C, H>(v, w, committee.id.into())
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);
        let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new(k);
        let plaintext = aes_gcm::aead::Aead::decrypt(&cipher, nonce, data.as_ref());
        plaintext
            .map(Plaintext)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Decryption failed: {:?}", e)))
    }
}

// TODO: Replace with actual hash to curve
// (see. https://datatracker.ietf.org/doc/rfc9380/)
fn hash_to_curve<C, H>(v: C, e: Vec<u8>) -> Result<C, ThresholdEncError>
where
    C: CurveGroup,
    H: Digest + Default + Clone + FixedOutputReset + 'static,
{
    let gen = C::generator();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    let _ = writer.write(&e);
    writer.flush()?;
    drop(writer);
    let hasher = <DefaultFieldHasher<H> as HashToField<C::ScalarField>>::new(&[0u8]);
    let scalar_from_hash: C::ScalarField = hasher.hash_to_field::<1>(&buffer)[0];
    let u_hat = gen * scalar_from_hash;
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
    use std::num::NonZeroUsize;

    use crate::{
        cp_proof::Proof,
        sg_encryption::{DecShare, Keyset, Plaintext, ShoupGennaro},
        traits::threshold_enc::ThresholdEncScheme,
    };

    use ark_std::rand::seq::SliceRandom;
    use ark_std::test_rng;
    use nimue::hash::legacy::DigestBridge;
    use sha2::Sha256;

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
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee, &pk, &plaintext).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message =
            ShoupGennaro::<G, H, D>::combine(&committee, &comb_key, dec_shares_refs, &ciphertext)
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
        let committee = Keyset::new(0, NonZeroUsize::new(10).unwrap());

        // setup schemes
        let (pk, comb_key, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee, &pk, &plaintext).unwrap();

        let threshold = committee.threshold().get();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext))
            .filter_map(|res| res.ok())
            .take(threshold) // not enough shares to combine
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let result =
            ShoupGennaro::<G, H, D>::combine(&committee, &comb_key, dec_shares_refs, &ciphertext);
        assert!(
            result.is_err(),
            "Should fail to combine; insufficient amount of shares"
        );
    }

    #[test]
    fn test_combine_invalid_shares() {
        let rng = &mut test_rng();
        let committee = Keyset::new(0, NonZeroUsize::new(10).unwrap());

        // setup schemes
        let (pk, comb_key, key_shares) = ShoupGennaro::<G, H, D>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let ciphertext =
            ShoupGennaro::<G, H, D>::encrypt(rng, &committee, &pk, &plaintext).unwrap();

        let mut dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        // 1. Change the order of the shares received by combiner
        dec_shares.shuffle(rng);

        let check_message = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "Combine should be indifferent to the order of incoming shares"
        );

        // 2. Invalidate n - t shares
        let c_size = committee.size().get();
        let c_threshold = committee.threshold().get();
        let first_correct_share = dec_shares[0].clone();
        // modify n - t shares
        (0..(c_size - c_threshold)).for_each(|i| {
            let mut share: DecShare<_> = dec_shares[i].clone();
            share.phi = Proof { transcript: vec![] };
            dec_shares[i] = share;
        });
        let result = ShoupGennaro::<G, H, D>::combine(
            &committee,
            &comb_key,
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
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
        );
        assert!(
            result.is_ok(),
            "Should succeed; we have exactly t+1 valid shares"
        );
    }
}
